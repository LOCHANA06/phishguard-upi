import os, sqlite3, json, pickle, random, string, socket, base64
from datetime import datetime, timedelta
from functools import wraps
import numpy as np
import requests as rq
import cv2
from flask import Flask, request, jsonify
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__, static_folder="static", static_url_path="")
from flask_cors import CORS
CORS(app)

DB = "phishguard.db"
MODEL_FILE = "phishguard_model.pkl"
START_BALANCE = 50000.0

RESEND_API_KEY = os.environ.get("RESEND_API_KEY", "")
TWILIO_SID     = os.environ.get("TWILIO_ACCOUNT_SID", "")
TWILIO_TOKEN   = os.environ.get("TWILIO_AUTH_TOKEN", "")
TWILIO_FROM    = os.environ.get("TWILIO_FROM", "")

# ---------------- DB ----------------
def db():
    c = sqlite3.connect(DB)
    c.row_factory = sqlite3.Row
    c.execute("PRAGMA foreign_keys=ON")
    return c

def init_db():
    """Create tables; self-heal legacy schemas from older versions of the app."""
    with db() as c:
        tables = {r["name"] for r in c.execute("SELECT name FROM sqlite_master WHERE type='table'")}

        # Drop old-version tables that lack user_id (they break inserts)
        legacy = False
        for t in ("recipients", "transactions", "reports"):
            if t in tables:
                cols = {r["name"] for r in c.execute(f"PRAGMA table_info({t})")}
                if "user_id" not in cols:
                    legacy = True
                    break
        if legacy:
            for t in ("reports", "transactions", "recipients", "alerts"):
                c.execute(f"DROP TABLE IF EXISTS {t}")

        c.executescript("""
        CREATE TABLE IF NOT EXISTS users(
            id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, email TEXT UNIQUE,
            phone TEXT, pw_hash TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS tokens(
            token TEXT PRIMARY KEY, user_id INTEGER, created_at TEXT);
        CREATE TABLE IF NOT EXISTS recipients(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, upi_id TEXT,
            name TEXT, verified INTEGER DEFAULT 0, blacklisted INTEGER DEFAULT 0,
            txn_count INTEGER DEFAULT 0, first_seen TEXT);
        CREATE TABLE IF NOT EXISTS transactions(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, upi_id TEXT,
            name TEXT, amount REAL, note TEXT, risk INTEGER, level TEXT,
            status TEXT, reasons TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS reports(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, upi_id TEXT,
            category TEXT, details TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS alerts(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, level TEXT,
            title TEXT, body TEXT, channels TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS otps(
            id INTEGER PRIMARY KEY AUTOINCREMENT, user_id INTEGER, pay_ref TEXT,
            code TEXT, expires_at TEXT, used INTEGER DEFAULT 0);
        """)

        # add balance column to existing users table if missing
        ucols = {r["name"] for r in c.execute("PRAGMA table_info(users)")}
        if "balance" not in ucols:
            c.execute(f"ALTER TABLE users ADD COLUMN balance REAL DEFAULT {START_BALANCE}")

# ---------------- auth helper ----------------
def auth(f):
    @wraps(f)
    def w(*a, **k):
        tok = request.headers.get("Authorization", "").replace("Bearer ", "")
        with db() as c:
            row = c.execute("SELECT user_id FROM tokens WHERE token=?", (tok,)).fetchone()
        if not row:
            return jsonify(error="unauthorized"), 401
        request.user_id = row["user_id"]
        return f(*a, **k)
    return w

def seed_transactions(uid):
    """Seed 50 realistic sample transactions, then set balance so it tallies."""
    names = ["Swiggy", "Amazon Pay", "Flipkart", "Zomato", "Airtel", "Jio Recharge",
             "Uber", "IRCTC", "BigBasket", "Domino's", "BookMyShow", "Paytm Merchant",
             "RedBus", "Netflix", "Spotify", "Croma", "Reliance Digital", "Myntra",
             "Ajio", "KFC", "Vendors Mart", "Sri Traders", "Green Grocers",
             "MedPlus", "Apollo Pharmacy"]
    now = datetime.utcnow()
    rows = []
    for _ in range(50):
        d = now - timedelta(days=random.randint(0, 45), hours=random.randint(0, 23))
        amt = round(random.choice([49, 99, 149, 199, 249, 399, 549, 699, 999, 1499, 2499])
                    * random.uniform(0.8, 1.4), 2)
        n = random.choice(names)
        risk = random.choices([random.randint(2, 25), random.randint(40, 64),
                               random.randint(70, 95)], weights=[82, 13, 5])[0]
        level = "Low" if risk < 35 else ("Medium" if risk < 70 else "High")
        status = "Completed" if risk < 70 else random.choice(["Blocked", "Completed"])
        upi = n.lower().replace(" ", "").replace("'", "") + "@upi"
        rows.append((uid, upi, n, amt,
                     random.choice(["Payment", "Order", "Recharge", "Bill", "Food"]),
                     risk, level, status, json.dumps([]), d.isoformat()))
    with db() as c:
        c.executemany("""INSERT INTO transactions
            (user_id,upi_id,name,amount,note,risk,level,status,reasons,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)""", rows)
        # balance = start minus every completed seeded payment
        spent = c.execute("""SELECT COALESCE(SUM(amount),0) s FROM transactions
                             WHERE user_id=? AND status='Completed'""", (uid,)).fetchone()["s"]
        c.execute("UPDATE users SET balance=? WHERE id=?", (START_BALANCE - spent, uid))

def ensure_user_seeded(uid):
    with db() as c:
        exists = c.execute("SELECT 1 FROM transactions WHERE user_id=? LIMIT 1",
                           (uid,)).fetchone()
    if not exists:
        seed_transactions(uid)

# ---------------- alerts ----------------
def send_email(to, subject, body):
    if not RESEND_API_KEY:
        return "skipped (no RESEND_API_KEY)"
    try:
        r = rq.post("https://api.resend.com/emails",
                    headers={"Authorization": f"Bearer {RESEND_API_KEY}"},
                    json={"from": "onboarding@resend.dev", "to": [to],
                          "subject": subject, "text": body}, timeout=10)
        return "email sent" if r.ok else f"email failed ({r.status_code})"
    except Exception as e:
        return f"email error: {e}"

def send_sms(to, body):
    if not (TWILIO_SID and TWILIO_TOKEN and TWILIO_FROM):
        return "skipped (no Twilio keys)"
    try:
        r = rq.post(f"https://api.twilio.com/2010-04-01/Accounts/{TWILIO_SID}/Messages.json",
                    auth=(TWILIO_SID, TWILIO_TOKEN),
                    data={"From": TWILIO_FROM, "To": to, "Body": body}, timeout=10)
        return "sms sent" if r.ok else f"sms failed ({r.status_code})"
    except Exception as e:
        return f"sms error: {e}"

def push_alert(uid, level, title, body):
    with db() as c:
        u = c.execute("SELECT email, phone FROM users WHERE id=?", (uid,)).fetchone()
    ch = ["in-app"]
    if level in ("Medium", "High") and u:
        ch.append(send_email(u["email"], f"PhishGuard {level} Alert: {title}", body))
        ch.append(send_sms(u["phone"], f"PhishGuard {level} Alert: {title}"))
    with db() as c:
        c.execute("""INSERT INTO alerts(user_id,level,title,body,channels,created_at)
                     VALUES(?,?,?,?,?,?)""",
                  (uid, level, title, body, json.dumps(ch), datetime.utcnow().isoformat()))
    return ch

# ---------------- risk engine ----------------
model = None
try:
    with open(MODEL_FILE, "rb") as fh:
        model = pickle.load(fh)
except Exception:
    pass

TRUSTED = {"paytm.com", "amazonpay.in", "phonepe.com", "googlepay.com",
           "bharatpe.in", "swiggy.com"}
PHISH_WORDS = ["kyc", "verify", "suspend", "refund", "lucky", "winner",
               "urgent", "otp", "block", "bonus"]
BAD_TLDS = ("tk", "xyz", "top", "club", "online", "site", "info", "buzz", "icu")

def domain_intel(domain):
    out = {"resolves": False, "age_days": None, "http_ok": False}
    if not domain:
        return out
    try:
        socket.getaddrinfo(domain, 443)
        out["resolves"] = True
    except Exception:
        pass
    try:
        r = rq.get(f"https://rdap.org/domain/{domain}", timeout=6,
                   headers={"Accept": "application/rdap+json"})
        if r.ok:
            for ev in r.json().get("events", []):
                if ev.get("eventAction") == "registration":
                    out["age_days"] = (datetime.utcnow() -
                        datetime.strptime(ev["eventDate"][:10], "%Y-%m-%d")).days
    except Exception:
        pass
    try:
        r = rq.head(f"https://{domain}", timeout=5, allow_redirects=True)
        out["http_ok"] = r.status_code < 500
    except Exception:
        pass
    return out

def analyze_payload(uid, data):
    v = (data.get("value") or "").strip()
    amount = float(data.get("amount") or 0)
    reasons, score = [], 0
    low = v.lower()

    upi = ""
    if "@" in v:
        for tok in v.replace("?", " ").replace("=", " ").replace("&", " ").split():
            if "@" in tok:
                upi = tok.split("/")[-1]
                break
    with db() as c:
        rec = (c.execute("SELECT * FROM recipients WHERE upi_id=? AND user_id=?",
                         (upi, uid)).fetchone() if upi else None)
        known = rec is not None
        verified = bool(rec and rec["verified"])
        blacklisted = bool(rec and rec["blacklisted"])
        txn_count = rec["txn_count"] if rec else 0
        first_seen = rec["first_seen"] if rec else None
        avg = (c.execute("SELECT AVG(amount) a FROM transactions WHERE user_id=?",
                         (uid,)).fetchone()["a"]) or 300

    if blacklisted:
        reasons.append("Recipient was reported earlier and is blacklisted.")
        score += 55
    if upi and not known:
        reasons.append(f"Unfamiliar recipient handle ({upi}) — no prior transaction history.")
        score += 22
    if upi and known and not verified and txn_count < 2:
        reasons.append("Recipient has limited transaction history with you.")
        score += 12
    if amount > max(avg * 3, 1000):
        reasons.append(f"Amount ₹{amount:,.0f} is far above your normal pattern (~₹{avg:,.0f}).")
        score += 18
    h = datetime.now().hour
    if 0 <= h < 6:
        reasons.append("Transaction attempted during unusual hours (12–6 AM).")
        score += 10

    domain = ""
    if low.startswith("http") or "www." in low:
        try:
            domain = v.split("//")[1].split("/")[0].replace("www.", "")
        except Exception:
            pass
    if domain:
        intel = domain_intel(domain)
        if domain.split(".")[-1] in BAD_TLDS:
            reasons.append(f"Domain uses a high-risk extension (.{domain.split('.')[-1]}).")
            score += 20
        if "upi" in domain or "pay" in domain:
            reasons.append("Domain impersonates a payment brand in its name.")
            score += 15
        if any(wd in low for wd in PHISH_WORDS):
            reasons.append("Payment link contains phishing keywords (kyc/verify/urgent).")
            score += 18
        if not intel["resolves"]:
            reasons.append("Domain does not resolve in DNS — likely fake or expired.")
            score += 25
        elif intel["age_days"] is not None and intel["age_days"] < 30:
            reasons.append(f"Domain registered only {intel['age_days']} days ago.")
            score += 20
        if intel["age_days"] is not None and intel["age_days"] > 365:
            score -= 8

    if data.get("type") == "qr" and "upi://" in low and "pa=" not in low:
        reasons.append("QR payload is not a valid UPI deep-link (missing pa= parameter).")
        score += 20

    score = max(2, min(97, score))

    if model is not None and amount > 0:
        try:
            feats = np.array([[np.log1p(amount), 1 if 0 <= h < 6 else 0, txn_count / 10,
                               30 if not first_seen else
                               (datetime.utcnow() - datetime.fromisoformat(first_seen)).days,
                               0, 0, 0.1, 1 if verified else 0, 1 if blacklisted else 0,
                               0, 0.8 if domain in TRUSTED else 0.2,
                               0, 0, 1 if any(wd in low for wd in PHISH_WORDS) else 0,
                               1 if amount > avg * 3 else 0]])
            p = float(model.predict_proba(feats)[0][1])
            score = int(round(0.62 * p * 100 + 0.38 * score))
            score = max(2, min(97, score))
        except Exception:
            pass

    level = "Low" if score < 35 else ("Medium" if score < 70 else "High")
    if level == "High" and not reasons:
        reasons.append("ML model flags this pattern as matching known phishing behaviour.")
    return {"risk": score, "level": level, "reasons": reasons, "upi": upi, "domain": domain}

# ---------------- auth routes ----------------
@app.post("/api/signup")
def signup():
    d = request.get_json(force=True)
    name = d.get("name", "").strip()
    email = d.get("email", "").strip().lower()
    phone = d.get("phone", "").strip()
    pw = d.get("password", "")
    if not (name and email and phone and len(pw) >= 6):
        return jsonify(error="All fields required; password min 6 chars."), 400
    if not email.endswith(".com") and "@" not in email:
        return jsonify(error="Enter a valid email address."), 400
    with db() as c:
        if c.execute("SELECT 1 FROM users WHERE email=?", (email,)).fetchone():
            return jsonify(error="Email already registered — please sign in."), 400
        cur = c.execute("""INSERT INTO users(name,email,phone,pw_hash,balance,created_at)
                           VALUES(?,?,?,?,?,?)""",
                        (name, email, phone, generate_password_hash(pw),
                         START_BALANCE, datetime.utcnow().isoformat()))
        uid = cur.lastrowid
    seed_transactions(uid)
    push_alert(uid, "Low", "Welcome to PhishGuard",
               f"Account created for {name}. Real-time UPI protection is now active.")
    return auth_response(uid, name)

@app.post("/api/login")
def login():
    d = request.get_json(force=True)
    with db() as c:
        u = c.execute("SELECT * FROM users WHERE email=?",
                      (d.get("email", "").strip().lower(),)).fetchone()
    if not u or not check_password_hash(u["pw_hash"], d.get("password", "")):
        return jsonify(error="Invalid email or password."), 401
    ensure_user_seeded(u["id"])
    return auth_response(u["id"], u["name"])

def auth_response(uid, name):
    tok = "".join(random.choices(string.ascii_letters + string.digits, k=48))
    with db() as c:
        c.execute("INSERT INTO tokens(token,user_id,created_at) VALUES(?,?,?)",
                  (tok, uid, datetime.utcnow().isoformat()))
    return jsonify(token=tok, user={"id": uid, "name": name})


@app.post("/api/logout")
@auth
def logout():
    tok = request.headers.get("Authorization", "").replace("Bearer ", "")
    with db() as c:
        c.execute("DELETE FROM tokens WHERE token=?", (tok,))
    return jsonify(ok=True)

# ---------------- dashboard ----------------
@app.get("/api/dashboard")
@auth
def dashboard():
    uid = request.user_id
    with db() as c:
        txns = c.execute("""SELECT * FROM transactions WHERE user_id=?
                            ORDER BY created_at DESC LIMIT 60""", (uid,)).fetchall()
        stats = c.execute("""
            SELECT COUNT(*) total, COALESCE(SUM(amount),0) vol,
                   SUM(CASE WHEN risk>=70 THEN 1 ELSE 0 END) high,
                   SUM(CASE WHEN risk>=35 AND risk<70 THEN 1 ELSE 0 END) med,
                   SUM(CASE WHEN status='Completed' THEN 1 ELSE 0 END) completed
                   FROM transactions WHERE user_id=?""", (uid,)).fetchone()
        al = c.execute("SELECT COUNT(*) n FROM alerts WHERE user_id=?", (uid,)).fetchone()["n"]
        bal = c.execute("SELECT balance FROM users WHERE id=?", (uid,)).fetchone()["balance"]
    return jsonify(stats={"total": stats["total"], "volume": round(stats["vol"], 2),
                          "high": stats["high"], "medium": stats["med"],
                          "completed": stats["completed"], "alerts": al,
                          "balance": round(bal, 2)},
                   transactions=[dict(t) for t in txns])

# ---------------- QR decode (server-side OpenCV fallback) ----------------
@app.post("/api/decode")
@auth
def decode_qr_photo():
    img_b64 = request.get_json(force=True).get("image", "")
    try:
        arr = np.frombuffer(base64.b64decode(img_b64.split(",")[-1]), np.uint8)
        img = cv2.imdecode(arr, cv2.IMREAD_COLOR)
        if img is None:
            return jsonify(error="Could not read image."), 400
        det = cv2.QRCodeDetector()
        # try original, then preprocessed variants (phone photos are tricky)
        for frame in _qr_variants(img):
            data, _, _ = det.detectAndDecode(frame)
            if data:
                return jsonify(value=data)
        return jsonify(error="No QR code found in the photo."), 400
    except Exception:
        return jsonify(error="Could not process image."), 400

def _qr_variants(img):
    yield img
    gray = cv2.cvtColor(img, cv2.COLOR_BGR2GRAY)
    yield gray
    h, w = gray.shape
    if max(h, w) > 1400:
        s = 1400 / max(h, w)
        gray = cv2.resize(gray, (int(w * s), int(h * s)))
    _, th = cv2.threshold(gray, 0, 255, cv2.THRESH_BINARY + cv2.THRESH_OTSU)
    yield th
    yield cv2.resize(th, None, fx=0.5, fy=0.5)

# ---------------- analyze ----------------
@app.post("/api/analyze")
@auth
def analyze():
    d = request.get_json(force=True)
    res = analyze_payload(request.user_id, d)
    if res["level"] == "High":
        push_alert(request.user_id, "High", "Potential phishing detected",
                   f"Risk {res['risk']}/100 — " + " ".join(res["reasons"][:2]))
    return jsonify(res)

# ---------------- pay ----------------
@app.post("/api/pay")
@auth
def pay():
    d = request.get_json(force=True)
    uid = request.user_id
    upi = d.get("upi_id", "").strip()
    amt = float(d.get("amount") or 0)
    if not upi or "@" not in upi or amt <= 0:
        return jsonify(error="Enter a valid UPI ID and amount."), 400
    res = analyze_payload(uid, {"type": "pay", "value": upi, "amount": amt})
    with db() as c:
        rec = c.execute("SELECT name, verified FROM recipients WHERE upi_id=? AND user_id=?",
                        (upi, uid)).fetchone()
    name = d.get("name") or (rec["name"] if rec else upi.split("@")[0].title())
    if rec and rec["verified"]:
        res["reasons"] = []
    pay_ref = "PG" + "".join(random.choices(string.digits, k=10))
    status = ("blocked" if res["level"] == "High"
              else "success" if res["level"] == "Low" else "verify")

    if status == "success":
        with db() as c:
            bal = c.execute("SELECT balance FROM users WHERE id=?", (uid,)).fetchone()["balance"]
            if bal < amt:
                return jsonify(error="Insufficient balance."), 400
            c.execute("UPDATE users SET balance=balance-? WHERE id=?", (amt, uid))
        push_alert(uid, "Low", f"Payment of ₹{amt:,.0f} completed",
                   f"Paid to {upi} ({name}).")
    elif status == "verify":
        code = "".join(random.choices(string.digits, k=6))
        with db() as c:
            c.execute("""INSERT INTO otps(user_id,pay_ref,code,expires_at)
                         VALUES(?,?,?,?)""",
                      (uid, pay_ref, code,
                       (datetime.utcnow() + timedelta(minutes=5)).isoformat()))
        push_alert(uid, "Medium", f"Verify payment of ₹{amt:,.0f}",
                   f"Confirmation code: {code} (valid 5 min). Recipient: {upi}.")
        res["dev_code"] = code   # shown only when no email/SMS provider is configured

    with db() as c:
        c.execute("""INSERT INTO transactions
            (user_id,upi_id,name,amount,note,risk,level,status,reasons,created_at)
            VALUES(?,?,?,?,?,?,?,?,?,?)""",
                  (uid, upi, name, amt, d.get("note", "Payment"), res["risk"],
                   res["level"],
                   {"success": "Completed", "verify": "Pending",
                    "blocked": "Blocked"}[status],
                   json.dumps(res["reasons"]), datetime.utcnow().isoformat()))
    return jsonify(pay_ref=pay_ref,
                   recipient={"upi": upi, "name": name}, amount=amt,
                   status=status, **res)

@app.post("/api/pay/confirm")
@auth
def pay_confirm():
    d = request.get_json(force=True)
    with db() as c:
        o = c.execute("""SELECT * FROM otps WHERE pay_ref=? AND user_id=? AND used=0
                         ORDER BY id DESC""", (d.get("pay_ref"), request.user_id)).fetchone()
        if not o:
            return jsonify(error="No pending verification."), 400
        if o["code"] != (d.get("code", "").strip()):
            return jsonify(error="Incorrect code."), 400
        if datetime.fromisoformat(o["expires_at"]) < datetime.utcnow():
            return jsonify(error="Code expired — start the payment again."), 400
        c.execute("UPDATE otps SET used=1 WHERE id=?", (o["id"],))
        # complete the pending txn exactly once, and deduct exactly once
        cur = c.execute("""UPDATE transactions SET status='Completed'
                           WHERE user_id=? AND upi_id=? AND status='Pending'""",
                        (request.user_id, d.get("upi_id", "")))
        if cur.rowcount:
            amt = float(d.get("amount") or 0)
            c.execute("""UPDATE users SET balance=balance-?
                         WHERE id=? AND balance>=?""", (amt, request.user_id, amt))
    push_alert(request.user_id, "Low", "Payment authorized after verification",
               f"Payment {d.get('pay_ref')} completed after extra confirmation.")
    return jsonify(ok=True, status="success")

# ---------------- alerts ----------------
@app.get("/api/alerts")
@auth
def alerts():
    with db() as c:
        rows = c.execute("""SELECT * FROM alerts WHERE user_id=?
                            ORDER BY id DESC LIMIT 40""", (request.user_id,)).fetchall()
    return jsonify(alerts=[dict(a) for a in rows])

# ---------------- reports ----------------
@app.post("/api/report")
@auth
def report():
    d = request.get_json(force=True)
    upi = d.get("upi_id", "").strip()
    if "@" not in upi:
        return jsonify(error="Enter a valid UPI ID."), 400
    with db() as c:
        c.execute("""INSERT INTO reports(user_id,upi_id,category,details,created_at)
                     VALUES(?,?,?,?,?)""",
                  (request.user_id, upi, d.get("category", "Other"),
                   d.get("details", ""), datetime.utcnow().isoformat()))
        exists = c.execute("SELECT 1 FROM recipients WHERE upi_id=? AND user_id=?",
                           (upi, request.user_id)).fetchone()
        if exists:
            c.execute("""UPDATE recipients SET blacklisted=1
                         WHERE upi_id=? AND user_id=?""", (upi, request.user_id))
        else:
            c.execute("""INSERT INTO recipients(user_id,upi_id,name,blacklisted,first_seen)
                         VALUES(?,?,?,1,?)""",
                      (request.user_id, upi, upi.split("@")[0].title(),
                       datetime.utcnow().isoformat()))
    push_alert(request.user_id, "Medium", "Fraud report filed",
               f"{upi} blacklisted after your report ({d.get('category', 'Other')}).")
    return jsonify(ok=True,
                   message=f"{upi} has been blacklisted. Future payments to it will be blocked.")

@app.get("/api/reports")
@auth
def my_reports():
    with db() as c:
        rows = c.execute("""SELECT * FROM reports WHERE user_id=?
                            ORDER BY id DESC LIMIT 25""", (request.user_id,)).fetchall()
    return jsonify(reports=[dict(r) for r in rows])

@app.get("/")
def home():
    return app.send_static_file("index.html")

init_db()
if __name__ == "__main__":
    init_db()
    port = int(os.environ.get("PORT", 5000))
    app.run(debug=False, port=port, host="0.0.0.0")

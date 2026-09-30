import os, re, json, sqlite3, pickle, hashlib, random
from datetime import datetime, timedelta
from urllib.parse import urlparse, parse_qs, unquote
from flask import Flask, request, jsonify, send_from_directory

APP_DIR = os.path.dirname(os.path.abspath(__file__))
DB_PATH = os.path.join(APP_DIR, "phishguard.db")
MODEL_PATH = os.path.join(APP_DIR, "phishguard_model.pkl")

app = Flask(__name__, static_folder="static", static_url_path="")

# ---------------- Database ----------------
def db():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with db() as c:
        c.executescript("""
        CREATE TABLE IF NOT EXISTS recipients(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            upi_id TEXT UNIQUE, name TEXT, verified INTEGER DEFAULT 0,
            blacklisted INTEGER DEFAULT 0, first_seen TEXT,
            txn_count INTEGER DEFAULT 0, total_amount REAL DEFAULT 0);
        CREATE TABLE IF NOT EXISTS transactions(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ref TEXT UNIQUE, amount REAL, upi_id TEXT, payee_name TEXT,
            merchant_name TEXT, source TEXT, domain TEXT,
            device_id TEXT, location TEXT, hour INTEGER,
            risk_score REAL, risk_level TEXT, status TEXT,
            reasons TEXT, created_at TEXT);
        CREATE TABLE IF NOT EXISTS reports(
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            upi_id TEXT, reason TEXT, details TEXT, created_at TEXT);
        """)
        seed = [
            ("swiggy@icici",  "Swiggy",        1, 0),
            ("amazonpay@apl", "Amazon Pay",    1, 0),
            ("paytmqr@ptys",  "Paytm Merchant",1, 0),
            ("quickrewards@ybl", "Quick Rewards",0, 1),
            ("fastag.kyc@okaxis","FASTag KYC Desk",0, 1),
        ]
        known = [
            ("rahul@okhdfc", "Rahul Sharma", 1, 0),
            ("mom@ybl", "Sunita Verma", 1, 0),
        ]
        now = datetime.utcnow().isoformat()
        for upi, name, v, b in seed + known:
            c.execute("INSERT OR IGNORE INTO recipients(upi_id,name,verified,blacklisted,first_seen,txn_count,total_amount) VALUES(?,?,?,?,?,?,?)",
                      (upi, name, v, b, now, 0, 0))
        # user history so "unusual amount / frequency" works out of the box
        for i in range(14):
            c.execute("INSERT OR IGNORE INTO transactions(ref,amount,upi_id,payee_name,merchant_name,source,domain,device_id,location,hour,risk_score,risk_level,status,reasons,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                      (f"HIST{i:03d}", random.choice([120,250,340,480,650]), "swiggy@icici", "Swiggy", "Swiggy",
                       "app", "", "DEV001", "Mumbai", 13, 12.0, "Low", "allowed", "[]",
                       (datetime.utcnow()-timedelta(days=i+1)).isoformat()))

# ---------------- ML model ----------------
with open(MODEL_PATH, "rb") as f:
    _m = pickle.load(f)
MODEL, FEATURE_NAMES = _m["model"], _m["features"]

# ---------------- Domain / link intelligence ----------------
TRUSTED_DOMAINS = {"paytm.com","razorpay.com","phonepe.com","bharatpe.com","amazonpay.in",
                   "pay.google.com","cashfree.com","billdesk.com","juspay.in","paypal.com"}
SUSPICIOUS_TLDS = {"tk","xyz","top","buzz","click","loan","icu","cf","ml","ga","gq","work","fit"}
PHISH_KEYWORDS = ["kyc","verify","suspend","blocked","refund","lottery","cashback","urgent",
                  "winner","reward","updat","secure","login","otp","limit","restore"]

def _sigmoid(x): return 1/(1+np_exp(-x)) if (np_exp:=__import__("math").exp) else 0

def domain_trust_score(domain):
    if not domain: return 0.5
    d = domain.lower()
    if d in TRUSTED_DOMAINS: return 1.0
    tld = d.rsplit(".",1)[-1]
    if tld in SUSPICIOUS_TLDS: return 0.05
    if re.match(r"^\d+\.\d+\.\d+\.\d+$", d): return 0.02
    if any(k in d for k in ["paytm","phonepe","upi"]) and d not in TRUSTED_DOMAINS: return 0.1  # lookalike
    return 0.45

def analyze_link_signals(url):
    sig, reasons = {}, []
    try:
        p = urlparse(url if "//" in url else "//"+url, scheme="http")
        host, path = (p.netloc or "").lower(), (p.path or "") + (p.query or "")
    except Exception:
        host, path, url = "", "", url
    sig["ip_host"] = 1 if re.match(r"^\d+\.\d+\.\d+\.\d+$", host) else 0
    tld = host.rsplit(".",1)[-1] if "." in host else ""
    sig["suspicious_tld"] = 1 if tld in SUSPICIOUS_TLDS else 0
    hits = [k for k in PHISH_KEYWORDS if k in url.lower()]
    sig["link_keywords"] = 1 if hits else 0
    sig["domain_trust"] = domain_trust_score(host)
    if sig["ip_host"]: reasons.append(f"The payment link uses a raw IP address ({host}) instead of a genuine domain.")
    if sig["suspicious_tld"]: reasons.append(f"The domain uses a high-risk '.{tld}' extension commonly abused in phishing.")
    if hits: reasons.append(f"The link contains phishing keywords: {', '.join(hits[:3])}.")
    if sig["domain_trust"] < 0.2 and not sig["ip_host"]:
        reasons.append(f"The domain '{host}' is untrusted or impersonates a payment provider.")
    return sig, reasons, host

def parse_upi_payload(text):
    """Parse upi://pay?pa=...&pn=...&am=... or a raw upi id."""
    text = unquote(text or "").strip()
    if text.lower().startswith("upi://"):
        q = parse_qs(urlparse(text).query)
        return q.get("pa",[""])[0], q.get("pn",[""])[0], q.get("am",[None])[0], q.get("cu",[""])[0], text
    if "@" in text:
        return text, "", None, "", text
    return "", "", None, "", text

def name_similarity(a, b):
    a, b = (a or "").lower().strip(), (b or "").strip().lower()
    if not a or not b: return 1.0
    return 1.0 if a == b else (0.5 if a in b or b in a else 0.0)

# ---------------- Core risk engine ----------------
def analyze_transaction(data):
    upi_id, payee, amt_str, _cu, raw = parse_upi_payload(data.get("payload") or data.get("upi_id",""))
    try: amount = float(amt_str or data.get("amount") or 0)
    except ValueError: amount = 0.0
    merchant = (data.get("merchant_name") or payee or "").strip()
    source   = data.get("source","app")            # qr | link | app
    device   = data.get("device_id","DEV001")
    location = data.get("location","Mumbai")
    url      = data.get("url","")
    domain, host = "", ""
    link_reasons = []
    if source == "link" and url:
        lsig, link_reasons, host = analyze_link_signals(url)
        domain = host
    else:
        lsig = {"ip_host":0,"suspicious_tld":0,"link_keywords":0,"domain_trust":0.5}

    now = datetime.utcnow()
    with db() as c:
        rec = c.execute("SELECT * FROM recipients WHERE upi_id=?", (upi_id,)).fetchone()
        hist = c.execute("SELECT amount, device_id, location, created_at FROM transactions WHERE status='allowed' ORDER BY id DESC LIMIT 30").fetchall()
        vel_24h = c.execute("SELECT COUNT(*) n FROM transactions WHERE created_at > ?",
                            ((now-timedelta(hours=24)).isoformat(),)).fetchone()["n"]

    verified    = rec["verified"] if rec else 0
    blacklisted = rec["blacklisted"] if rec else 0
    txn_count   = rec["txn_count"] if rec else 0
    age_days    = max((now - datetime.fromisoformat(rec["first_seen"])).days, 0) if rec else 0
    name_match  = 0.0
    name_mismatch = 0
    if rec and merchant:
        name_match = name_similarity(rec["name"], merchant)
        name_mismatch = 0 if name_match >= 0.5 else 1
    known_devices = {h["device_id"] for h in hist}
    known_locs    = {h["location"] for h in hist}
    new_device, new_location = int(device not in known_devices), int(location not in known_locs)
    amounts = [h["amount"] for h in hist if h["amount"]]
    avg_amt = sum(amounts)/len(amounts) if amounts else amount or 300
    amount_anomaly = int(amount > max(3*avg_amt, avg_amt+2000)) if amount else 0
    odd_hour = 1 if now.hour < 6 or now.hour >= 23 else 0
    velocity = min(vel_24h/10.0, 1.0)
    import math
    log_amount = math.log10(max(amount, 1))

    feats = [[log_amount, odd_hour, min(txn_count,10)/10, min(age_days,365)/365,
              new_device, new_location, velocity, verified, blacklisted, name_mismatch,
              lsig["domain_trust"], lsig["ip_host"], lsig["suspicious_tld"],
              lsig["link_keywords"], amount_anomaly]]
    ml_prob = float(MODEL.predict_proba(feats)[0][1])

    # ---- Rule engine: human-readable reasons ----
    reasons = list(link_reasons)
    if blacklisted: reasons.append("The recipient has been reported by users and is on the fraud blacklist.")
    if not rec:     reasons.append(f"The recipient '{upi_id or 'unknown'}' is not in your payment history or the verified merchant directory.")
    if name_mismatch: reasons.append(f"Merchant name '{merchant}' does not match registered payee '{rec['name']}'.")
    if amount_anomaly: reasons.append(f"The amount ₹{amount:,.0f} is far higher than your normal pattern (avg ₹{avg_amt:,.0f}).")
    if odd_hour: reasons.append("This payment is being made at an unusual time (late night/early morning).")
    if new_device: reasons.append("The payment request comes from a device not previously used.")
    if new_location: reasons.append("The transaction originates from an unfamiliar location.")
    if velocity >= 0.5: reasons.append("Unusually high number of payment attempts in the last 24 hours.")
    if source == "qr" and not rec: reasons.append("The QR code redirects to an unfamiliar payment handle.")
    if amount == 0 and source == "qr": reasons.append("The QR code has no amount pinned — attackers often edit it later.")

    rule_score = min(1.0, 0.22*blacklisted + 0.25*(0 if rec else 1) + 0.2*name_mismatch +
                     0.15*amount_anomaly + 0.08*odd_hour + 0.08*new_device + 0.05*new_location +
                     0.2*(1-lsig["domain_trust"]) + 0.1*lsig["ip_host"] + 0.05*velocity)
    risk = round(min(99.0, 100*(0.62*ml_prob + 0.38*rule_score) + random.uniform(-1.5,1.5)), 1)
    risk = max(3.0, risk)
    level = "High" if risk >= 70 else ("Medium" if risk >= 35 else "Low")
    status = "blocked" if risk >= 85 else ("needs_confirmation" if risk >= 70 else "allowed")
    reasons = reasons[:4] if level != "High" else reasons[:5] or ["Behavioral model flagged this transaction as anomalous."]

    ref = "TXN" + hashlib.md5((raw+str(now)).encode()).hexdigest()[:8].upper()
    with db() as c:
        c.execute("INSERT INTO transactions(ref,amount,upi_id,payee_name,merchant_name,source,domain,device_id,location,hour,risk_score,risk_level,status,reasons,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                  (ref, amount, upi_id, payee, merchant, source, domain, device, location, now.hour,
                   risk, level, status, json.dumps(reasons), now.isoformat()))
        if rec and status == "allowed":
            c.execute("UPDATE recipients SET txn_count=txn_count+1, total_amount=total_amount+? WHERE upi_id=?", (amount, upi_id))
    return {"ref": ref, "risk_score": risk, "risk_level": level, "status": status,
            "reasons": reasons, "upi_id": upi_id, "amount": amount,
            "merchant": merchant, "source": source, "domain": domain,
            "recommended_action": {
                "blocked": "Transaction BLOCKED. Do not retry. Report this recipient immediately.",
                "needs_confirmation": "Verify this payment with an extra confirmation step before it proceeds.",
                "allowed": "Safe to proceed. No action needed."}[status]}

# ---------------- API ----------------
@app.post("/api/analyze")
def api_analyze():
    return jsonify(analyze_transaction(request.get_json(force=True)))

@app.post("/api/confirm/<ref>")
def api_confirm(ref):
    with db() as c:
        row = c.execute("SELECT * FROM transactions WHERE ref=?", (ref,)).fetchone()
        if not row: return jsonify({"error":"not found"}), 404
        c.execute("UPDATE transactions SET status='confirmed_allowed' WHERE ref=?", (ref,))
        if row["upi_id"]:
            c.execute("UPDATE recipients SET txn_count=txn_count+1, total_amount=total_amount+? WHERE upi_id=?",
                      (row["amount"], row["upi_id"]))
    return jsonify({"ref": ref, "status": "confirmed_allowed", "message": "Payment authorized after verification."})

@app.post("/api/report")
def api_report():
    d = request.get_json(force=True)
    with db() as c:
        c.execute("INSERT INTO reports(upi_id,reason,details,created_at) VALUES(?,?,?,?)",
                  (d.get("upi_id",""), d.get("reason",""), d.get("details",""), datetime.utcnow().isoformat()))
        if d.get("upi_id"):
            c.execute("UPDATE recipients SET blacklisted=1 WHERE upi_id=?", (d["upi_id"],))
    return jsonify({"message": "Report submitted. Recipient flagged for review."})

@app.get("/api/dashboard")
def api_dashboard():
    with db() as c:
        txns = [dict(r) for r in c.execute("SELECT * FROM transactions ORDER BY id DESC LIMIT 25")]
        stats = dict(c.execute("""SELECT COUNT(*) total,
            SUM(CASE WHEN risk_level='High' THEN 1 ELSE 0 END) high,
            SUM(CASE WHEN status='blocked' THEN 1 ELSE 0 END) blocked,
            SUM(CASE WHEN status='allowed' THEN 1 ELSE 0 END) allowed,
            AVG(risk_score) avg_risk FROM transactions""").fetchone())
        alerts = [t for t in txns if t["risk_level"] in ("High","Medium")]
    return jsonify({"transactions": txns, "alerts": alerts, "stats": stats})

@app.get("/api/recipients")
def api_recipients():
    with db() as c:
        return jsonify([dict(r) for r in c.execute("SELECT * FROM recipients")])

@app.get("/")
def home():
    return send_from_directory("static", "index.html")

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)

# First, ignore files that shouldn't go up
echo -e "phishguard.db\nphishguard_model.pkl\n__pycache__/\nvenv/" > .gitignore

git init
git add .
git commit -m "PhishGuard UPI prototype"
git branch -M main
git remote add origin https://github.com/LOCHANA06/phishguard-upi.git
git push -u origin main

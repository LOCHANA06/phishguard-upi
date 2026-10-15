// Same-origin API when served by Flask (local/preview/Render); absolute URL only inside the APK
const IN_APK = !!(window && window.Capacitor) ||   // Android + iOS native shell
  location.protocol === "capacitor:" ||
  (location.hostname === "localhost" && location.protocol === "https:");
const API = IN_APK ? "https://phishguard-upi.onrender.com" : "";
let token = localStorage.getItem("pg_token") || "";
let scanner = null, payRef = null, balanceVisible = true, repCategory = "Phishing QR code";

const $ = id => document.getElementById(id);
const show = el => el.classList.remove("hidden");
const hide = el => el.classList.add("hidden");

/* ================= API ================= */
async function api(path, body, method = "POST") {
  const res = await fetch(API + path, {
    method,
    headers: { "Content-Type": "application/json", "Authorization": "Bearer " + token },
    body: body ? JSON.stringify(body) : undefined
  });
  const data = await res.json().catch(() => ({}));
  if (res.status === 401 && !path.startsWith("/api/login") && !path.startsWith("/api/signup")) {
    doLogout(true);
    const err = new Error("Session expired — please sign in again."); err.status = 401; throw err;
  }
  if (!res.ok) {
    const err = new Error(data.error || `Request failed (${res.status})`);
    err.status = res.status; throw err;
  }
  return data;
}

/* ================= STATE CLEARING (per-user isolation) ================= */
function clearUserState() {
  ["payUpi", "payName", "payAmt", "payNote", "verCode", "linkInput", "repUpi", "repDetails"]
    .forEach(id => { const el = $(id); if (el) el.value = ""; });
  [["payUpi", "payUpiMsg"], ["payAmt", "payAmtMsg"]].forEach(([inp, msg]) => {
    const i = $(inp), m = $(msg);
    if (i) i.classList.remove("input-val-error", "input-val-success");
    if (m) { m.textContent = ""; m.className = "val-msg"; }
  });
  ["linkResult", "scanResult", "repMsg"].forEach(id => {
    const el = $(id); if (el) { el.innerHTML = ""; el.classList.add("hidden"); }
  });
  hide($("payStepVerify")); hide($("payStepDone")); hide($("payStepBlocked"));
  hide($("utrBackdrop"));
  show($("payStepForm"));
  ["delPw", "delConfirm", "fi_code", "fi_pw"].forEach(id => { const el = $(id); if (el) el.value = ""; });
  ["delMsg", "fi_msg"].forEach(id => { const el = $(id); if (el) el.textContent = ""; });
  const rum = $("realUpiMsg"); if (rum) { rum.textContent = ""; rum.className = "val-msg"; }
  window._dir = null; hide($("dirWrap"));
}

/* ================= AUTH ================= */
$("tabLogin").onclick = () => switchTab(true);
$("tabSignup").onclick = () => switchTab(false);
function switchTab(login) {
  $("tabLogin").classList.toggle("active", login);
  $("tabSignup").classList.toggle("active", !login);
  hide($("forgotForm")); $("li_ok").textContent = "";
  if (login) { show($("loginForm")); hide($("signupForm")); }
  else { show($("signupForm")); hide($("loginForm")); }
}

$("loginForm").onsubmit = async e => {
  e.preventDefault(); $("li_err").textContent = ""; $("li_ok").textContent = "";
  try { enterApp(await api("/api/login", { email: $("li_email").value, password: $("li_pw").value })); }
  catch (err) { $("li_err").textContent = err.message; }
};

$("signupForm").onsubmit = async e => {
  e.preventDefault(); $("su_err").textContent = "";
  try { enterApp(await api("/api/signup", { name: $("su_name").value, email: $("su_email").value,
    phone: $("su_phone").value, password: $("su_pw").value })); }
  catch (err) { $("su_err").textContent = err.message; }
};

function enterApp(r) {
  token = r.token;
  localStorage.setItem("pg_token", token);
  localStorage.setItem("pg_user", r.user.name || "User");
  clearUserState();
  hide($("authScreen")); show($("appScreen"));
  $("userChip").textContent = r.user.name || "User";
  loadDashboard().catch(e => console.error(e));
}

function doLogout(expired) {
  if (!expired && token) api("/api/logout").catch(() => {});
  token = "";
  localStorage.removeItem("pg_token");
  localStorage.removeItem("pg_user");
  clearUserState();
  hide($("appScreen")); show($("authScreen"));
  $("userChip").textContent = "";
}
$("logoutBtn").onclick = () => doLogout(false);

if (token) {
  api("/api/dashboard", null, "GET")
    .then(d => {
      show($("appScreen")); hide($("authScreen"));
      $("userChip").textContent = localStorage.getItem("pg_user") || "User";
      renderDashboard(d);
    })
    .catch(() => { token = ""; localStorage.removeItem("pg_token"); });
}

/* ================= NAV ================= */
document.querySelectorAll(".nav-btn, .nav-go").forEach(b => b.onclick = () => goPage(b.dataset.page));
$("viewAllBtn").onclick = () => goPage("transactions");
function goPage(page) {
  document.querySelectorAll(".nav-btn").forEach(x => x.classList.toggle("active", x.dataset.page === page));
  document.querySelectorAll(".page").forEach(p => p.classList.add("hidden"));
  show($("page-" + page));
  if (page === "dashboard") loadDashboard().catch(() => {});
  if (page === "transactions") loadTransactions().catch(() => {});
  if (page === "alerts") loadAlerts().catch(() => {});
  if (page === "report") loadReports().catch(() => {});
  if (page === "settings") loadSettings().catch(() => {});
  if (page !== "scan") stopScan();
}

/* ================= DASHBOARD / BALANCE ================= */
async function loadDashboard() { renderDashboard(await api("/api/dashboard", null, "GET")); }

const amtHTML = t => t.direction === "credit"
  ? `<b style="color:#16A34A">+₹${Number(t.amount).toLocaleString("en-IN")}</b>`
  : `−₹${Number(t.amount).toLocaleString("en-IN")}`;
const partyHTML = t => t.direction === "credit"
  ? `<span class="party-in"><svg class="icon"><use href="#i-arrow-in"/></svg>${t.name}</span>`
  : t.name;

function renderDashboard(d) {
  window._balance = d.stats.balance;
  if (d.profile && d.profile.upi_id)
    $("balSub").innerHTML =
      `PhishGuard Demo Bank •••• 4821 · <b class="mono" title="Your UPI handle — share it to get paid">${d.profile.upi_id}</b>`;
  $("balAmount").textContent = balanceVisible
    ? "₹" + Number(d.stats.balance).toLocaleString("en-IN", { minimumFractionDigits: 2 })
    : "₹ ••••••";
  $("payBalChip").textContent = "Bal: ₹" +
    Number(d.stats.balance).toLocaleString("en-IN", { maximumFractionDigits: 0 });
  $("statGrid").innerHTML = `
    <div class="stat"><span class="n">${d.stats.total}</span><span class="l">Transactions</span></div>
    <div class="stat ok"><span class="n">${d.stats.completed}</span><span class="l">Completed</span></div>
    <div class="stat ok"><span class="n">₹${Number(d.stats.received || 0).toLocaleString("en-IN", { maximumFractionDigits: 0 })}</span><span class="l">Money In</span></div>
    <div class="stat warn"><span class="n">${d.stats.medium}</span><span class="l">Medium Risk</span></div>
    <div class="stat bad"><span class="n">${d.stats.high}</span><span class="l">Blocked</span></div>
    <div class="stat"><span class="n">${d.stats.alerts}</span><span class="l">Alerts Sent</span></div>`;
  $("recentBody").innerHTML = d.transactions.slice(0, 6).map(t => `
    <tr><td>${new Date(t.created_at).toLocaleDateString("en-IN", { day: "numeric", month: "short" })}</td>
    <td><b>${partyHTML(t)}</b></td><td>${amtHTML(t)}</td>
    <td><span class="pill ${t.level.toLowerCase()}">${t.level} · ${t.risk}</span></td>
    <td><span class="status s-${t.status.toLowerCase()}">${t.status}</span></td></tr>`).join("");
  if (!window._dir) loadDirectory().catch(() => {});
}
$("eyeBtn").onclick = () => {
  balanceVisible = !balanceVisible;
  $("balAmount").textContent = balanceVisible
    ? "₹" + Number(window._balance || 0).toLocaleString("en-IN", { minimumFractionDigits: 2 })
    : "₹ ••••••";
  $("eyeBtn").querySelector("use").setAttribute("href", balanceVisible ? "#i-eye" : "#i-eye-off");
};

/* ================= TRANSACTIONS PAGE ================= */
async function loadTransactions() {
  const d = await api("/api/dashboard", null, "GET");
  renderTxns(d.transactions);
}
function renderTxns(list) {
  const f = $("txnFilter").value;
  let rows = list;
  if (f === "risk:High") rows = list.filter(t => t.level === "High");
  else if (f === "risk:Medium") rows = list.filter(t => t.level === "Medium");
  else if (f !== "all") rows = list.filter(t => t.status === f);
  $("txnBody").innerHTML = rows.map(t => `
    <tr><td>${new Date(t.created_at).toLocaleDateString("en-IN", { day: "numeric", month: "short" })}</td>
    <td><b>${partyHTML(t)}</b></td><td class="mono">${t.upi_id}</td>
    <td>${amtHTML(t)}</td>
    <td><span class="pill ${t.level.toLowerCase()}">${t.level} · ${t.risk}</span></td>
    <td><span class="status s-${t.status.toLowerCase()}">${t.status}</span></td></tr>`).join("")
    || `<tr><td colspan="6" class="muted" style="text-align:center">No transactions.</td></tr>`;
}
$("txnFilter").onchange = () => loadTransactions().catch(() => {});

/* ================= RESULT RENDER ================= */
function resultHTML(title, r) {
  const color = r.level === "High" ? "#DC2626" : r.level === "Medium" ? "#F59E0B" : "#16A34A";
  return `<div class="card"><h3>${title}</h3><div class="result-row">
    <div class="gauge" style="background:conic-gradient(${color} ${r.risk * 3.6}deg, #E2E8F0 0deg)">
      <div class="gauge-in"><b>${r.risk}</b><span>/100</span></div></div>
    <div style="flex:1;min-width:240px">
      <div class="risk-banner ${r.level.toLowerCase()}">Risk level: ${r.level} — ${r.risk}/100</div>
      ${r.reasons && r.reasons.length
        ? `<ul class="reasons">${r.reasons.map(x => `<li>${x}</li>`).join("")}</ul>`
        : `<div class="risk-banner low"><svg class="icon"><use href="#i-check"/></svg>No suspicious signals — recipient, amount and context look normal.</div>`}
      ${r.level === "High" ? `<p class="rec">Recommended action: verify the recipient before authorizing this payment.</p>` : ""}
    </div></div></div>`;
}

/* ================= SCAN QR ================= */
$("startCam").onclick = () => {
  scanner = new Html5Qrcode("qrReader");
  scanner.start({ facingMode: "environment" }, { fps: 10, qrbox: 250 }, onQrDecoded)
    .then(() => { show($("stopCam")); $("startCam").textContent = "Scanning…"; })
    .catch(e => {
      $("scanResult").innerHTML =
        `<div class="card"><div class="risk-banner high">Camera unavailable here (${e}). Use <b>Analyze QR Photo</b> — or open via localhost / HTTPS.</div></div>`;
      show($("scanResult"));
    });
};
$("stopCam").onclick = stopScan;
function stopScan() {
  if (scanner) { scanner.stop().then(() => scanner.clear()).catch(() => {}); scanner = null; }
  hide($("stopCam"));
  $("startCam").textContent = "Start Camera Scan";
}
async function onQrDecoded(text) { stopScan(); showQrResult(text); }
function showQrResult(text) {
  api("/api/analyze", { type: "qr", value: text }).then(r => {
    $("scanResult").innerHTML = `<div class="card"><p class="mono">Decoded: ${text}</p></div>` + resultHTML("QR Analysis Result", r);
    show($("scanResult"));
    $("scanResult").scrollIntoView({ behavior: "smooth" });
  }).catch(err => alert(err.message));
}

$("qrPhoto").onchange = async e => {
  const f = e.target.files[0]; if (!f) return;
  const dataUrl = await new Promise(res => {
    const r = new FileReader(); r.onload = () => res(r.result); r.readAsDataURL(f);
  });
  const text = await decodePhotoJsQR(dataUrl);
  if (text) return showQrResult(text);
  try {
    const d = await api("/api/decode", { image: dataUrl });
    showQrResult(d.value);
  } catch (err) {
    $("scanResult").innerHTML =
      `<div class="card"><div class="risk-banner high">No QR code detected — try a sharper, closer photo.</div></div>`;
    show($("scanResult"));
  }
  e.target.value = "";
};
function decodePhotoJsQR(dataUrl) {
  return new Promise(resolve => {
    const img = new Image();
    img.onload = () => {
      const max = 1200, scale = Math.min(1, max / Math.max(img.width, img.height));
      const c = document.createElement("canvas");
      c.width = Math.round(img.width * scale); c.height = Math.round(img.height * scale);
      const ctx = c.getContext("2d", { willReadFrequently: true });
      ctx.drawImage(img, 0, 0, c.width, c.height);
      const d = ctx.getImageData(0, 0, c.width, c.height);
      const code = jsQR(d.data, c.width, c.height);
      resolve(code ? code.data : null);
    };
    img.onerror = () => resolve(null);
    img.src = dataUrl;
  });
}

/* ================= ANALYZE LINK ================= */
$("analyzeLinkBtn").onclick = async () => {
  const v = $("linkInput").value.trim(); if (!v) return;
  $("analyzeLinkBtn").textContent = "Analyzing…"; $("analyzeLinkBtn").disabled = true;
  try {
    const r = await api("/api/analyze", { type: "link", value: v });
    $("linkResult").innerHTML = resultHTML("Link Analysis Result", r);
    show($("linkResult"));
  } catch (err) { alert(err.message); }
  $("analyzeLinkBtn").textContent = "Analyze"; $("analyzeLinkBtn").disabled = false;
};

/* ================= PAY ANYONE ================= */
async function loadDirectory() {
  const d = await api("/api/directory", null, "GET");
  window._dir = d.users || [];
  if (!window._dir.length) return;
  $("dirList").innerHTML = window._dir.map(u =>
    `<button type="button" class="chip" data-upi="${u.upi_id}" data-name="${u.name}">${u.name}</button>`).join("");
  show($("dirWrap"));
  document.querySelectorAll("#dirList .chip").forEach(b => b.onclick = () => {
    $("payUpi").value = b.dataset.upi;
    $("payName").value = b.dataset.name;
    setVal($("payUpi"), $("payUpiMsg"), true, `Registered PhishGuard user — ${b.dataset.name}`);
    $("payAmt").focus();
  });
}

function setVal(input, msgEl, ok, msg) {
  input.classList.toggle("input-val-error", !ok);
  input.classList.toggle("input-val-success", ok);
  msgEl.textContent = msg;
  msgEl.className = "val-msg " + (ok ? "ok" : "err");
}
$("payUpi").addEventListener("input", e => {
  const v = e.target.value.trim();
  if (!v) { e.target.classList.remove("input-val-error", "input-val-success"); $("payUpiMsg").textContent = ""; return; }
  const match = (window._dir || []).find(u => u.upi_id.toLowerCase() === v.toLowerCase());
  if (match) {
    setVal(e.target, $("payUpiMsg"), true, `Registered PhishGuard user — ${match.name}`);
    return;
  }
  const ok = /^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}$/.test(v);
  setVal(e.target, $("payUpiMsg"), ok,
    v.includes("@") ? (v.split("@")[1].length > 1 ? "Valid UPI handle" : "Bank handle looks incomplete") : "Format: name@bank");
});
$("payAmt").addEventListener("input", e => {
  const v = parseFloat(e.target.value);
  if (!e.target.value) { e.target.classList.remove("input-val-error", "input-val-success"); $("payAmtMsg").textContent = ""; return; }
  const bal = window._balance || 0;
  setVal(e.target, $("payAmtMsg"), v > 0 && v <= bal,
    v > bal ? "Exceeds your balance" : v > 0 ? "Amount OK" : "Enter an amount above ₹0");
});

$("payBtn").onclick = () => {
  const upi = $("payUpi").value.trim(), amt = parseFloat($("payAmt").value);
  if (!/^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}$/.test(upi)) {
    setVal($("payUpi"), $("payUpiMsg"), false, "Enter a valid UPI ID (name@bank)"); return;
  }
  if (!amt || amt <= 0 || amt > (window._balance || 0)) {
    setVal($("payAmt"), $("payAmtMsg"), false, "Check the amount — must be within your balance"); return;
  }
  const name = $("payName").value.trim() || upi.split("@")[0].replace(/[._]/g, " ").replace(/\b\w/g, c => c.toUpperCase());
  $("sheetName").textContent = name;
  $("sheetUpi").textContent = upi;
  $("sheetAmt").textContent = "₹" + amt.toLocaleString("en-IN");
  $("sheetAvatar").textContent = name[0].toUpperCase();
  show($("sheetBackdrop"));
};
$("sheetCancel").onclick = () => hide($("sheetBackdrop"));

document.querySelectorAll(".pay-app").forEach(b => b.onclick = async () => {
  hide($("sheetBackdrop")); show($("payProcessing"));
  $("procText").textContent = `Paying via ${b.dataset.app}…`;
  await new Promise(r => setTimeout(r, 1600));
  try {
    const r = await api("/api/pay", {
      upi_id: $("payUpi").value.trim(), name: $("payName").value.trim(),
      amount: parseFloat($("payAmt").value), note: $("payNote").value, app: b.dataset.app
    });
    payRef = r.pay_ref;
    hide($("payProcessing"));
    if (r.status === "success") return payDone(r);
    if (r.status === "blocked") {
      $("blkReasons").innerHTML = (r.reasons || []).map(x => `<li>${x}</li>`).join("")
        || "<li>High-risk pattern detected.</li>";
      show($("payStepBlocked")); return;
    }
    $("verReasons").innerHTML = (r.reasons || []).map(x => `<li>${x}</li>`).join("");
    show($("payStepVerify"));
  } catch (err) { hide($("payProcessing")); alert(err.message); }
});

$("verSubmit").onclick = async () => {
  try {
    await api("/api/pay/confirm", { pay_ref: payRef, code: $("verCode").value,
      upi_id: $("payUpi").value.trim(), amount: parseFloat($("payAmt").value) });
    payDone({ amount: $("payAmt").value, upi: $("payUpi").value.trim() });
  } catch (err) { alert(err.message); }
};

function payDone(r) {
  $("doneMeta").textContent = `₹${Number(r.amount).toLocaleString("en-IN")} paid to ${r.upi}` +
    (r.credited ? " — receiver balance credited instantly" : "");
  hide($("payStepVerify"));
  show($("payStepDone"));
  loadDashboard().catch(() => {});
}
$("doneAgain").onclick = $("blkBack").onclick = () => {
  hide($("payStepDone")); hide($("payStepBlocked"));
  clearUserState();
  show($("payStepForm"));
};

/* ================= ALERTS ================= */
async function loadAlerts() {
  const d = await api("/api/alerts", null, "GET");
  $("alertList").innerHTML = d.alerts.map(a => `
    <div class="alert-item ${a.level.toLowerCase()}">
      <div class="alert-head"><b>${a.title}</b><span class="pill ${a.level.toLowerCase()}">${a.level}</span></div>
      <p>${a.body}</p>
      <p class="muted" style="font-size:.78rem">${new Date(a.created_at).toLocaleString("en-IN")}</p>
    </div>`).join("") || `<p class="muted">No alerts yet.</p>`;
}

/* ================= REPORT FRAUD ================= */
document.querySelectorAll("#repCats .chip").forEach(c => c.onclick = () => {
  document.querySelectorAll("#repCats .chip").forEach(x => x.classList.remove("sel"));
  c.classList.add("sel");
  repCategory = c.dataset.cat;
});
$("repBtn").onclick = async () => {
  try {
    const r = await api("/api/report", { upi_id: $("repUpi").value.trim(),
      category: repCategory, details: $("repDetails").value });
    $("repMsg").textContent = r.message; show($("repMsg"));
    $("repUpi").value = ""; $("repDetails").value = "";
    loadReports().catch(() => {});
  } catch (err) { $("repMsg").textContent = err.message; show($("repMsg")); }
};
async function loadReports() {
  const d = await api("/api/reports", null, "GET");
  $("repHistory").innerHTML = d.reports.map(r => `
    <div class="rep-item"><b class="mono">${r.upi_id}</b><span class="pill high">${r.category}</span>
    <p class="muted" style="font-size:.8rem">${r.details || "—"} · ${new Date(r.created_at).toLocaleDateString("en-IN")}</p></div>`).join("")
    || `<p class="muted">No reports filed yet.</p>`;
}

/* ================= FORGOT / RESET PASSWORD ================= */
$("forgotBtn").onclick = () => {
  $("tabLogin").classList.remove("active"); $("tabSignup").classList.remove("active");
  hide($("loginForm")); hide($("signupForm")); hide($("resetStep2"));
  $("fi_msg").textContent = ""; $("fi_msg").className = "form-err";
  show($("forgotForm"));
  $("fi_email").focus();
};
$("backLoginBtn").onclick = () => switchTab(true);
$("sendCodeBtn").onclick = async () => {
  const email = $("fi_email").value.trim();
  if (!email) { $("fi_msg").className = "form-err"; $("fi_msg").textContent = "Enter your account email."; return; }
  $("sendCodeBtn").disabled = true; $("sendCodeBtn").textContent = "Sending…";
  try {
    const r = await api("/api/forgot", { email });
    show($("resetStep2"));
    $("fi_msg").className = "form-ok";
    $("fi_msg").textContent = r.dev_code
      ? `Demo mode — reset code: ${r.dev_code}`
      : "Reset code sent to your email.";
    $("fi_code").focus();
  } catch (err) { $("fi_msg").className = "form-err"; $("fi_msg").textContent = err.message; }
  $("sendCodeBtn").disabled = false; $("sendCodeBtn").textContent = "Send reset code";
};
$("forgotForm").onsubmit = async e => {
  e.preventDefault();
  $("fi_msg").textContent = ""; $("fi_msg").className = "form-err";
  try {
    await api("/api/reset", { email: $("fi_email").value.trim(),
      code: $("fi_code").value.trim(), password: $("fi_pw").value });
    switchTab(true);
    $("li_email").value = $("fi_email").value.trim();
    $("li_ok").textContent = "Password reset — sign in with your new password.";
    $("li_pw").focus();
  } catch (err) { $("fi_msg").textContent = err.message; }
};

/* ================= SETTINGS / REAL UPI ID / DELETE ACCOUNT ================= */
async function loadSettings() {
  const d = await api("/api/dashboard", null, "GET");
  const p = d.profile || {};
  $("profKv").innerHTML = `
    <div class="kv-row"><span>Name</span><b>${p.name || "—"}</b></div>
    <div class="kv-row"><span>Email</span><b>${p.email || "—"}</b></div>
    <div class="kv-row"><span>Phone</span><b>${p.phone || "—"}</b></div>
    <div class="kv-row"><span>PhishGuard handle</span><b class="mono">${p.upi_id || "—"}</b></div>
    <div class="kv-row"><span>Real UPI ID</span><b class="mono">${p.real_upi || "not linked"}</b></div>`;
  $("realUpiInput").value = p.real_upi || "";
}
$("saveRealUpi").onclick = async () => {
  try {
    const r = await api("/api/account/real-upi", { real_upi: $("realUpiInput").value.trim() });
    setVal($("realUpiInput"), $("realUpiMsg"), true, r.message);
    window._dir = null;                       // directory chips refresh on next dashboard load
    loadSettings().catch(() => {});
  } catch (err) { setVal($("realUpiInput"), $("realUpiMsg"), false, err.message); }
};
$("delBtn").onclick = async () => {
  $("delMsg").textContent = "";
  if ($("delConfirm").value.trim().toUpperCase() !== "DELETE") {
    $("delMsg").textContent = "Type DELETE to confirm."; return;
  }
  if (!$("delPw").value) { $("delMsg").textContent = "Enter your password to confirm."; return; }
  if (!confirm("Permanently delete your PhishGuard account and ALL data? This cannot be undone.")) return;
  $("delBtn").disabled = true;
  try {
    await api("/api/account/delete", { password: $("delPw").value });
    token = ""; localStorage.removeItem("pg_token"); localStorage.removeItem("pg_user");
    clearUserState(); hide($("appScreen")); show($("authScreen"));
    switchTab(true);
    $("li_ok").textContent = "Account and all data deleted permanently.";
    $("li_pw").value = "";
  } catch (err) { $("delMsg").textContent = err.message; }
  $("delBtn").disabled = false;
};

/* ================= REAL-MONEY UPI PAYMENT ================= */
let realRef = null;
$("payRealBtn").onclick = async () => {
  const upi = $("payUpi").value.trim(), amt = parseFloat($("payAmt").value);
  if (!/^[a-zA-Z0-9.\-_]{2,}@[a-zA-Z]{2,}$/.test(upi)) {
    setVal($("payUpi"), $("payUpiMsg"), false, "Enter a valid UPI ID (name@bank)"); return;
  }
  if (!amt || amt <= 0 || amt > (window._balance || 0)) {
    setVal($("payAmt"), $("payAmtMsg"), false, "Check the amount — must be within your balance"); return;
  }
  hide($("sheetBackdrop")); show($("payProcessing"));
  $("procText").textContent = "Staging real-money transfer…";
  try {
    const r = await api("/api/pay/real", { upi_id: upi, name: $("payName").value.trim(),
      amount: amt, note: $("payNote").value });
    hide($("payProcessing"));
    if (r.status === "blocked") {
      $("blkReasons").innerHTML = (r.reasons || []).map(x => `<li>${x}</li>`).join("")
        || "<li>High-risk pattern detected — real-money transfer blocked.</li>";
      show($("payStepBlocked")); return;
    }
    realRef = r.pay_ref;
    $("utrMeta").textContent = `₹${amt.toLocaleString("en-IN")} to ${r.target} · reference ${r.pay_ref}`;
    $("utrInput").value = ""; $("utrMsg").textContent = "";
    show($("utrBackdrop"));
    // hand off to the device's UPI app (no-op on desktop — the UTR sheet explains the fallback)
    window.location.href = r.upi_link;
  } catch (err) { hide($("payProcessing")); alert(err.message); }
};
$("utrCancel").onclick = () => { hide($("utrBackdrop")); show($("sheetBackdrop")); };
$("utrSubmit").onclick = async () => {
  const utr = $("utrInput").value.trim();
  if (!/^\d{12}$/.test(ut)) {
    $("utrMsg").textContent = "UTR is the 12-digit reference shown in your UPI app after paying.";
    return;
  }
  $("utrSubmit").disabled = true;
  try {
    const r = await api("/api/pay/real/confirm", { pay_ref: realRef, utr });
    hide($("utrBackdrop"));
    payDone({ amount: r.amount, upi: r.upi });
  } catch (err) { $("utrMsg").textContent = err.message; }
  $("utrSubmit").disabled = false;
}

const API = "";
const $ = s => document.querySelector(s);

// ---------- Navigation ----------
document.querySelectorAll(".nav-btn, .back").forEach(btn =>
  btn.addEventListener("click", () => showPage(btn.dataset.page)));
function showPage(id){
  document.querySelectorAll(".page").forEach(p => p.classList.remove("active"));
  $("#page-" + id).classList.add("active");
  document.querySelectorAll(".nav-btn").forEach(b => b.classList.toggle("active", b.dataset.page === id));
  if (id === "dashboard") loadDashboard();
  if (id === "alerts") loadAlerts();
}

// ---------- Dashboard ----------
async function loadDashboard(){
  const d = await (await fetch(API + "/api/dashboard")).json();
  $("#st-total").textContent = d.stats.total ?? 0;
  $("#st-high").textContent = d.stats.high ?? 0;
  $("#st-blocked").textContent = d.stats.blocked ?? 0;
  $("#st-avg").textContent = (d.stats.avg_risk ?? 0).toFixed(1);
  const tb = $("#txn-table tbody"); tb.innerHTML = "";
  d.transactions.forEach(t => tb.appendChild(row(t)));
}
function row(t){
  const tr = document.createElement("tr");
  tr.innerHTML = `<td>${t.ref}</td><td>${t.merchant_name || t.upi_id || "—"}</td>
    <td>₹${(+t.amount).toLocaleString("en-IN")}</td><td>${t.source.toUpperCase()}</td>
    <td><span class="badge b-${t.risk_level.toLowerCase()}">${t.risk_level} · ${t.risk_score}</span></td>
    <td>${t.status.replace("_"," ")}</td>`;
  return tr;
}

// ---------- Alert renderer (shared) ----------
function alertCard(res){
  const g = res.risk_level === "High" ? "#e02b4b" : res.risk_level === "Medium" ? "#f59e0b" : "#12b76a";
  const reasons = res.reasons.map(r => `<li>${r}</li>`).join("");
  let actions = "";
  if (res.status === "needs_confirmation")
    actions = `<div class="row"><button class="btn confirm" onclick="confirmPay('${res.ref}')">✅ Verify & Authorize</button>
               <button class="btn ghost" onclick="showPage('report')">🚩 Report Instead</button></div>`;
  if (res.status === "blocked")
    actions = `<div class="row"><button class="btn danger" onclick="prefillReport('${res.upi_id}')">🚩 Report This Recipient</button>
               <button class="btn ghost" onclick="showPage('dashboard')">← Back to Dashboard</button></div>`;
  if (res.status === "allowed")
    actions = `<div class="row"><button class="btn confirm" onclick="alert('Payment of ₹${res.amount} authorized ✅')">Proceed with Payment</button></div>`;
  return `<div class="card result-card risk-${res.risk_level.toLowerCase()}">
    <h2>⚠️ Potential phishing transaction detected</h2>
    <p class="muted">Risk level: <b style="color:${g}">${res.risk_level} — ${res.risk_score}/100</b></p>
    <div class="gauge" style="background:conic-gradient(${g} ${res.risk_score*3.6}deg,#e8edf8 0)"><span style="color:${g};background:#fff;border-radius:50%;width:84px;height:84px;display:flex;align-items:center;justify-content:center">${res.risk_score}</span></div>
    <p><b>${res.merchant || res.upi_id}</b> · ₹${(+res.amount).toLocaleString("en-IN")} · via ${res.source.toUpperCase()}${res.domain ? " · " + res.domain : ""}</p>
    <p style="margin-top:10px;font-weight:600">This payment was flagged because:</p>
    <ul class="reason-list">${reasons}</ul>
    <div class="action-box">${res.recommended_action}</div>
    ${actions}</div>`;
}
async function confirmPay(ref){
  const r = await (await fetch(API + `/api/confirm/${ref}`, {method:"POST"})).json();
  $("#result-body").innerHTML = `<div class="card result-card risk-low"><h2>✅ Payment Authorized</h2><p class="muted">${r.message}</p></div>`;
}

// ---------- QR Scan flow: scan -> analyze -> RESULT PAGE ----------
$("#btn-scan").addEventListener("click", async () => {
  const frame = $(".qr-frame"); frame.classList.add("scanning");
  $("#btn-scan").disabled = true; $("#btn-scan").textContent = "Scanning…";
  const demos = ["upi://pay?pa=quickrewards@ybl&pn=Quick%20Rewards&am=4999",
                 "upi://pay?pa=swiggy@icici&pn=Swiggy&am=249"];
  const payload = demos[Math.floor(Math.random()*demos.length)];
  await new Promise(r => setTimeout(r, 2200));           // simulated camera scan
  const res = await (await fetch(API + "/api/analyze", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({payload, source:"qr", merchant_name: decodeURIComponent(payload.split("pn=")[1]?.split("&")[0] || "")})
  })).json();
  frame.classList.remove("scanning"); $("#btn-scan").disabled = false;
  $("#btn-scan").textContent = "Start Scan & Detect";
  $("#result-body").innerHTML = alertCard(res);
  showPage("result");
});

// ---------- Link analysis flow ----------
async function analyzeLink(url){
  const res = await (await fetch(API + "/api/analyze", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({url, source:"link", amount: 2499, merchant_name:"Online Store"})
  })).json();
  $("#result-body").innerHTML = alertCard(res);
  showPage("result");
}
$("#btn-link").addEventListener("click", () => analyzeLink($("#link-input").value.trim()));
$("#btn-link-demo").addEventListener("click", () => {
  $("#link-input").value = "http://192.168.4.22/paytm-kyc/verify?otp=urgent";
  analyzeLink($("#link-input").value);
});

// ---------- Transaction flow ----------
$("#btn-txn").addEventListener("click", async () => {
  const res = await (await fetch(API + "/api/analyze", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({amount:+$("#t-amount").value, upi_id:$("#t-upi").value,
      merchant_name:$("#t-name").value, location:$("#t-loc").value, source:"app"})
  })).json();
  $("#result-body").innerHTML = alertCard(res);
  showPage("result");
});

// ---------- Alerts page ----------
async function loadAlerts(){
  const d = await (await fetch(API + "/api/dashboard")).json();
  const box = $("#alert-list"); box.innerHTML = d.alerts.length ? "" : `<p class="muted">No alerts yet. All clear ✅</p>`;
  d.alerts.forEach(a => {
    const div = document.createElement("div");
    div.className = "alert-item" + (a.risk_level === "High" ? " high" : "");
    div.innerHTML = `<b>${a.risk_level} risk · ${a.risk_score}/100</b> — ${a.merchant_name || a.upi_id}
      (₹${(+a.amount).toLocaleString("en-IN")}, ${a.source})<ul class="reason-list">${JSON.parse(a.reasons).map(r=>`<li>${r}</li>`).join("")}</ul>
      <span class="badge b-${a.risk_level.toLowerCase()}">${a.status.replace("_"," ")}</span>`;
    box.appendChild(div);
  });
}

// ---------- Report flow ----------
window.prefillReport = upi => { $("#r-upi").value = upi; showPage("report"); };
$("#btn-report").addEventListener("click", async () => {
  const r = await (await fetch(API + "/api/report", {
    method:"POST", headers:{"Content-Type":"application/json"},
    body: JSON.stringify({upi_id:$("#r-upi").value, reason:$("#r-reason").value, details:$("#r-details").value})
  })).json();
  $("#report-msg").textContent = r.message;
});


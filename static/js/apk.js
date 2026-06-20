/* ═══════════════════════════════════════════════
   StegoDetect v2.0  —  apk.js
   APK Security Dashboard — upload, analyse, render
═══════════════════════════════════════════════ */

const apkDropZone  = document.getElementById("apkDropZone");
const apkInput     = document.getElementById("apkInput");
const apkPrevBar   = document.getElementById("apkPreviewBar");
const apkPrevName  = document.getElementById("apkPrevName");
const apkPrevSize  = document.getElementById("apkPrevSize");
const apkAnalyseBtn= document.getElementById("apkAnalyseBtn");

let selectedApk = null;

// ── Drag & Drop ──────────────────────────────────────────────
["dragenter","dragover"].forEach(e =>
  apkDropZone.addEventListener(e, ev => { ev.preventDefault(); apkDropZone.classList.add("drag-over"); }));
["dragleave","drop"].forEach(e =>
  apkDropZone.addEventListener(e, ev => { ev.preventDefault(); apkDropZone.classList.remove("drag-over"); }));
apkDropZone.addEventListener("drop", e => {
  const f = e.dataTransfer.files[0]; if (f) handleApk(f);
});
apkDropZone.addEventListener("click", () => apkInput.click());
apkInput.addEventListener("change", () => { if (apkInput.files[0]) handleApk(apkInput.files[0]); });

function handleApk(file) {
  const ext = file.name.split(".").pop().toLowerCase();
  if (ext !== "apk") { toast("Only .apk files are accepted here.", "error"); return; }
  selectedApk = file;
  apkPrevName.textContent    = file.name;
  apkPrevSize.textContent    = fmtBytes(file.size);
  apkPrevBar.style.display   = "flex";
  apkAnalyseBtn.disabled     = false;
  document.getElementById("apkResults").style.display = "none";
}

function clearApk() {
  selectedApk = null; apkInput.value = "";
  apkPrevBar.style.display   = "none";
  apkAnalyseBtn.disabled     = true;
  document.getElementById("apkResults").style.display = "none";
}

function resetApk() { clearApk(); window.scrollTo({ top: 0, behavior: "smooth" }); }

// ── Run APK Analysis ─────────────────────────────────────────
async function runApkAnalysis() {
  if (!selectedApk) return;

  const overlay = document.getElementById("apkLoadingOverlay");
  overlay.style.display = "flex";

  const steps = ["as1","as2","as3","as4","as5","as6","as7"];
  steps.forEach(s => document.getElementById(s)?.classList.remove("active","done"));
  let idx = 0;
  const timer = setInterval(() => {
    if (idx > 0) document.getElementById(steps[idx-1])?.classList.replace("active","done");
    if (idx < steps.length) { document.getElementById(steps[idx])?.classList.add("active"); idx++; }
  }, 500);

  const form = new FormData();
  form.append("apk", selectedApk);

  try {
    const res  = await fetch("/analyse-apk", { method: "POST", body: form });
    const data = await res.json();
    clearInterval(timer);
    steps.forEach(s => document.getElementById(s)?.classList.add("done"));
    await sleep(300);
    overlay.style.display = "none";

    if (data.error) { toast("Error: " + data.error, "error"); return; }
    renderApkResults(data);
  } catch (err) {
    clearInterval(timer);
    overlay.style.display = "none";
    toast("Network error. Is the server running?", "error");
  }
}

// ── Render APK Results ────────────────────────────────────────
function renderApkResults(d) {
  const sec = document.getElementById("apkResults");
  sec.style.display = "block";

  const riskColors = {
    Critical: { bg: "rgba(239,68,68,.12)",   border: "rgba(239,68,68,.5)",   text: "#ef4444",  icon: "🔴" },
    High:     { bg: "rgba(249,115,22,.12)",  border: "rgba(249,115,22,.5)",  text: "#f97316",  icon: "🟠" },
    Medium:   { bg: "rgba(234,179,8,.12)",   border: "rgba(234,179,8,.5)",   text: "#eab308",  icon: "🟡" },
    Low:      { bg: "rgba(16,185,129,.12)",  border: "rgba(16,185,129,.5)",  text: "#10b981",  icon: "🟢" },
  };
  const rc = riskColors[d.risk_level] || riskColors.Low;

  // ── Risk Banner ───────────────────────────────────────────
  const banner = document.getElementById("riskBanner");
  banner.style.background   = rc.bg;
  banner.style.borderColor  = rc.border;
  document.getElementById("riskIcon").textContent  = rc.icon;
  document.getElementById("riskLevel").textContent = `Risk Level: ${d.risk_level}`;
  document.getElementById("riskLevel").style.color = rc.text;
  document.getElementById("riskDesc").textContent  = riskDescription(d.risk_level, d);
  document.getElementById("riskScoreVal").textContent = d.risk_score;
  document.getElementById("riskScoreVal").style.color = rc.text;

  // ── App Overview ──────────────────────────────────────────
  const overviewItems = [
    { label: "Package Name",    value: d.package_name   || "Unknown", icon: "📱" },
    { label: "Version Name",    value: d.version_name   || "N/A",     icon: "🏷️" },
    { label: "Version Code",    value: d.version_code   || "N/A",     icon: "#️⃣" },
    { label: "Min SDK",         value: d.min_sdk        || "N/A",     icon: "📉" },
    { label: "Target SDK",      value: d.target_sdk     || "N/A",     icon: "🎯" },
    { label: "File Size",       value: (d.file_size_kb || 0) + " KB", icon: "💾" },
    { label: "Total Files",     value: d.file_count     || 0,         icon: "📂" },
    { label: "DEX Files",       value: d.dex_count      || 0,         icon: "⚙️" },
    { label: "Native Libs",     value: (d.native_libs || []).length,  icon: "🔧" },
    { label: "Analysis Time",   value: (d.proc_time_ms || 0) + " ms", icon: "⏱️" },
  ];
  document.getElementById("apkOverview").innerHTML = overviewItems.map(i =>
    `<div class="ov-item"><div class="ov-icon">${i.icon}</div><div class="ov-label">${i.label}</div><div class="ov-val">${escHtml(String(i.value))}</div></div>`
  ).join("");

  // ── Permissions ───────────────────────────────────────────
  const allPerms     = d.permissions || [];
  const dangerPerms  = d.dangerous_permissions || [];
  const normalPerms  = allPerms.filter(p => !dangerPerms.includes(p));

  document.getElementById("permTotalBadge").textContent =
    allPerms.length ? `${allPerms.length} total` : "0";

  if (dangerPerms.length) {
    document.getElementById("dangerPermsSection").style.display = "block";
    document.getElementById("dangerCount").textContent = `(${dangerPerms.length})`;
    document.getElementById("dangerPerms").innerHTML = dangerPerms.map(p =>
      `<span class="perm-tag perm-danger" title="${escHtml(p)}">${escHtml(shortPerm(p))}</span>`
    ).join("");
  } else {
    document.getElementById("dangerPermsSection").style.display = "none";
  }

  if (normalPerms.length) {
    document.getElementById("normalPermsSection").style.display = "block";
    document.getElementById("normalCount").textContent = `(${normalPerms.length})`;
    document.getElementById("normalPerms").innerHTML = normalPerms.map(p =>
      `<span class="perm-tag perm-normal" title="${escHtml(p)}">${escHtml(shortPerm(p))}</span>`
    ).join("");
  } else {
    document.getElementById("normalPermsSection").style.display = "none";
  }

  if (!allPerms.length) {
    document.getElementById("noPermsMsg").style.display = "block";
  } else {
    document.getElementById("noPermsMsg").style.display = "none";
  }

  // ── C2 IPs ────────────────────────────────────────────────
  const ips = (d.c2_indicators || {}).ips || [];
  document.getElementById("ipCount").textContent = ips.length ? `(${ips.length} found)` : "(none)";
  if (ips.length) {
    document.getElementById("ipTable").style.display    = "table";
    document.getElementById("noIpMsg").style.display   = "none";
    document.getElementById("ipTableBody").innerHTML   = ips.map((ip, i) =>
      `<tr>
        <td>${i+1}</td>
        <td><span class="ip-val">🌐 ${escHtml(ip)}</span></td>
        <td><span class="ip-type">Public IPv4</span></td>
        <td><span class="badge-red-sm">C2 Indicator</span></td>
      </tr>`
    ).join("");
  } else {
    document.getElementById("ipTable").style.display   = "none";
    document.getElementById("noIpMsg").style.display   = "block";
  }

  // ── C2 URLs ───────────────────────────────────────────────
  const urls = (d.c2_indicators || {}).urls || [];
  document.getElementById("urlCount").textContent = urls.length ? `(${urls.length} found)` : "(none)";
  if (urls.length) {
    document.getElementById("urlTable").style.display   = "table";
    document.getElementById("noUrlMsg").style.display  = "none";
    document.getElementById("urlTableBody").innerHTML  = urls.map((url, i) => {
      const proto = url.startsWith("https") ? "HTTPS" : "HTTP";
      const short = url.length > 70 ? url.slice(0, 70) + "…" : url;
      return `<tr>
        <td>${i+1}</td>
        <td><span class="url-val" title="${escHtml(url)}">🔗 ${escHtml(short)}</span></td>
        <td><span class="proto-badge ${proto === 'HTTPS' ? 'proto-https' : 'proto-http'}">${proto}</span></td>
      </tr>`;
    }).join("");
  } else {
    document.getElementById("urlTable").style.display   = "none";
    document.getElementById("noUrlMsg").style.display   = "block";
  }

  // ── Suspicious APIs ────────────────────────────────────────
  const apis = d.suspicious_apis || [];
  const apiIcons = {
    "Shell Execution":    "💻", "Dynamic Class Load": "📦",
    "Crypto Operations":  "🔑", "Base64 Decode":      "🔓",
    "SMS Access":         "💬", "Call Log Access":    "📞",
    "Contact Harvesting": "👥", "Location Tracking":  "📍",
    "Screen Capture":     "📸", "Audio Recording":    "🎙️",
    "Camera Capture":     "📷", "Device Fingerprint": "🔢",
    "Keylogging":         "⌨️", "Accessibility Abuse":"♿",
    "Device Admin":       "🔒", "Root Detection":     "🧪",
    "Anti-Emulation":     "🕶️", "Clipboard Access":   "📋",
    "Network Sniff":      "📡", "Obfuscation":        "🌀",
  };
  if (apis.length) {
    document.getElementById("noApiMsg").style.display  = "none";
    document.getElementById("susApiGrid").innerHTML    = apis.map(a =>
      `<div class="sus-api-item">
        <span class="sai-icon">${apiIcons[a] || "⚠️"}</span>
        <span class="sai-label">${escHtml(a)}</span>
      </div>`
    ).join("");
  } else {
    document.getElementById("noApiMsg").style.display  = "block";
    document.getElementById("susApiGrid").innerHTML    = "";
  }

  // ── File Structure ─────────────────────────────────────────
  const nativeLibs = d.native_libs || [];
  document.getElementById("apkStructGrid").innerHTML = [
    { icon: "⚙️", label: "DEX Bytecode Files",    value: d.dex_count || 0,    note: "Compiled Java/Kotlin code" },
    { icon: "📦", label: "Total Archive Entries",  value: d.file_count || 0,   note: "Files in APK ZIP" },
    { icon: "🔧", label: "Native Libraries (.so)", value: nativeLibs.length,   note: nativeLibs.slice(0,3).join(", ") || "None" },
    { icon: "💾", label: "APK File Size",          value: (d.file_size_kb||0)+" KB", note: "" },
  ].map(i =>
    `<div class="struct-item">
      <div class="si-icon">${i.icon}</div>
      <div class="si-body">
        <div class="si-label">${i.label}</div>
        <div class="si-val">${escHtml(String(i.value))}</div>
        ${i.note ? `<div class="si-note">${escHtml(i.note)}</div>` : ""}
      </div>
    </div>`
  ).join("");

  // ── Risk Summary ───────────────────────────────────────────
  const reasons = d.risk_reasons || [];
  const summary = document.getElementById("riskSummaryCard");
  summary.style.borderColor = rc.border;
  if (reasons.length) {
    document.getElementById("noRiskMsg").style.display    = "none";
    document.getElementById("riskReasonsList").innerHTML  = reasons.map((r, i) =>
      `<div class="risk-reason-item">
        <span class="rri-num">${i+1}</span>
        <span class="rri-text">${escHtml(r)}</span>
      </div>`
    ).join("");
  } else {
    document.getElementById("noRiskMsg").style.display   = "block";
    document.getElementById("riskReasonsList").innerHTML = "";
  }

  setTimeout(() => sec.scrollIntoView({ behavior: "smooth", block: "start" }), 200);
}

// ── Helpers ───────────────────────────────────────────────────
function shortPerm(p) {
  // android.permission.READ_SMS → READ_SMS
  return p.replace(/^android\.permission\./, "")
           .replace(/^.*\.permission\./, "")
           .replace(/^.*\./, "");
}

function riskDescription(level, d) {
  const dp  = (d.dangerous_permissions || []).length;
  const ips = ((d.c2_indicators || {}).ips || []).length;
  const apc = (d.suspicious_apis || []).length;
  if (level === "Critical")
    return `Highly malicious behaviour detected: ${dp} dangerous permission(s), ${ips} C2 IP(s), ${apc} suspicious API(s). Likely spyware or RAT.`;
  if (level === "High")
    return `Significant risk: ${dp} dangerous permission(s) and ${ips + apc} combined threat indicators found.`;
  if (level === "Medium")
    return `Moderate risk: some concerning patterns detected. Manual review recommended.`;
  return `Low risk: minimal threat indicators. App appears mostly benign.`;
}

function fmtBytes(b) {
  if (b < 1024) return b + " B";
  if (b < 1024*1024) return (b/1024).toFixed(1) + " KB";
  return (b/(1024*1024)).toFixed(1) + " MB";
}

function sleep(ms) { return new Promise(r => setTimeout(r, ms)); }

function escHtml(s) {
  return String(s)
    .replace(/&/g,"&amp;").replace(/</g,"&lt;").replace(/>/g,"&gt;")
    .replace(/"/g,"&quot;").replace(/'/g,"&#039;");
}

function toast(msg, type = "info") {
  const colors = { error:"#ef4444", success:"#10b981", info:"#00d2d3" };
  const el = document.createElement("div");
  el.style.cssText = `position:fixed;bottom:2rem;right:2rem;z-index:2000;padding:.9rem 1.4rem;border-radius:10px;font-size:.85rem;font-weight:600;background:${colors[type]||colors.info};color:#0a0e1a;box-shadow:0 8px 24px rgba(0,0,0,.4);max-width:340px`;
  el.textContent = msg;
  document.body.appendChild(el);
  setTimeout(() => el.remove(), 4000);
}

// ── Particles ─────────────────────────────────────────────────
(function() {
  const c = document.querySelector(".hero-grid");
  if (!c) return;
  const style = document.createElement("style");
  style.textContent = `@keyframes fp{0%,100%{opacity:.2;transform:translateY(0)}50%{opacity:.7;transform:translateY(-20px)}}`;
  document.head.appendChild(style);
  for (let i = 0; i < 25; i++) {
    const d  = document.createElement("div");
    const sz = Math.random()*3+1;
    d.style.cssText = `position:absolute;width:${sz}px;height:${sz}px;background:rgba(0,210,211,${Math.random()*.4+.1});border-radius:50%;left:${Math.random()*100}%;top:${Math.random()*100}%;animation:fp ${Math.random()*8+5}s ease-in-out infinite;animation-delay:${Math.random()*5}s;pointer-events:none`;
    c.appendChild(d);
  }
})();

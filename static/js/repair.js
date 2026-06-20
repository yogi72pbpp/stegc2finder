/* ═══════════════════════════════════════════════
   StegoDetect v2.0  —  repair.js
   File Reconstruction Dashboard
═══════════════════════════════════════════════ */

const repairDrop   = document.getElementById("repairDropZone");
const repairInput  = document.getElementById("repairInput");
const repairPrevBar= document.getElementById("repairPrevBar");
const repairBtn    = document.getElementById("repairBtn");

let selectedFile   = null;
let repairedB64    = null;   // base64 of repaired file (if small)
let repairDlUrl    = null;   // server-side download URL (if large)
let repairedExt    = "";

const FILE_ICONS = {
  image: "🖼️", pdf: "📄", office: "📝",
  audio: "🎵", video: "🎬", apk: "📦", default: "🗂️",
};

function categorise(name) {
  const ext = name.split(".").pop().toLowerCase();
  if (["png","jpg","jpeg","bmp","gif","tiff","webp","ico","avif"].includes(ext)) return "image";
  if (["pdf"].includes(ext))                                                      return "pdf";
  if (["doc","docx","odt","odf","ods","odp"].includes(ext))                       return "office";
  if (["mp3","wav","flac","ogg","aac","m4a","wma"].includes(ext))                 return "audio";
  if (["mp4","avi","mkv","mov","wmv","flv","webm","3gp"].includes(ext))           return "video";
  if (["apk","zip"].includes(ext))                                                return "apk";
  return "default";
}

// ── Drag & Drop ──────────────────────────────────────────────
["dragenter","dragover"].forEach(e =>
  repairDrop.addEventListener(e, ev => { ev.preventDefault(); repairDrop.classList.add("drag-over"); }));
["dragleave","drop"].forEach(e =>
  repairDrop.addEventListener(e, ev => { ev.preventDefault(); repairDrop.classList.remove("drag-over"); }));
repairDrop.addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if (f) handleRepairFile(f); });
repairDrop.addEventListener("click", () => repairInput.click());
repairInput.addEventListener("change", () => { if (repairInput.files[0]) handleRepairFile(repairInput.files[0]); });

function handleRepairFile(file) {
  selectedFile = file;
  repairedB64  = null;
  repairDlUrl  = null;

  const cat  = categorise(file.name);
  const icon = FILE_ICONS[cat] || FILE_ICONS.default;

  const iconEl = document.getElementById("repairPrevIcon");
  iconEl.textContent  = icon;
  iconEl.style.display= "flex";
  document.getElementById("repairPrevName").textContent = file.name;
  document.getElementById("repairPrevSize").textContent = fmtBytes(file.size);
  document.getElementById("repairPrevType").textContent = cat.toUpperCase();
  repairPrevBar.style.display  = "flex";
  repairBtn.disabled           = false;
  document.getElementById("repairResults").style.display = "none";
}

function clearRepair() {
  selectedFile = null; repairInput.value = "";
  repairPrevBar.style.display = "none";
  repairBtn.disabled          = true;
  document.getElementById("repairResults").style.display = "none";
}

function resetRepair() { clearRepair(); window.scrollTo({ top: 0, behavior: "smooth" }); }

// ── Run Repair ────────────────────────────────────────────────
async function runRepair() {
  if (!selectedFile) return;

  const overlay = document.getElementById("repairLoadingOverlay");
  overlay.style.display = "flex";

  const steps = ["rs1","rs2","rs3","rs4","rs5"];
  steps.forEach(s => document.getElementById(s)?.classList.remove("active","done"));
  let idx = 0;
  const timer = setInterval(() => {
    if (idx > 0) document.getElementById(steps[idx-1])?.classList.replace("active","done");
    if (idx < steps.length) { document.getElementById(steps[idx])?.classList.add("active"); idx++; }
  }, 500);

  const form = new FormData();
  form.append("file", selectedFile);

  try {
    const res  = await fetch("/repair-file", { method: "POST", body: form });
    const data = await res.json();
    clearInterval(timer);
    steps.forEach(s => document.getElementById(s)?.classList.add("done"));
    await sleep(300);
    overlay.style.display = "none";

    if (data.error) { toast("Error: " + data.error, "error"); return; }
    renderRepairResults(data);
  } catch (err) {
    clearInterval(timer);
    overlay.style.display = "none";
    toast("Network error. Is the server running?", "error");
  }
}

// ── Render Results ────────────────────────────────────────────
function renderRepairResults(d) {
  const sec = document.getElementById("repairResults");
  sec.style.display = "block";

  // Store repaired data for download
  repairedB64 = d.repaired_b64 || null;
  repairDlUrl = d.repair_download_url || null;
  repairedExt = (d.original_name || "file").split(".").pop().toLowerCase();

  const repaired    = d.repair_success;
  const hasCorrupt  = d.corruption_found && d.corruption_found.some(c => !/intact|valid|no corruption/i.test(c));

  // ── Banner ──────────────────────────────────────────────────
  const banner = document.getElementById("repairBanner");
  let bannerClass, icon, title, sub, badgeText, badgeClass;

  if (!d.signature_match && !repaired) {
    bannerClass = "rb-critical";
    icon = "🔴"; title = "Signature Mismatch — File Corrupted";
    sub  = `Expected ${d.expected_magic || "known signature"} — got ${d.actual_magic || "unknown bytes"}`;
    badgeText = "CORRUPTED"; badgeClass = "rb-badge-red";
  } else if (repaired && d.can_open) {
    bannerClass = "rb-success";
    icon = "✅"; title = "File Successfully Reconstructed";
    sub  = `${d.repairs_applied.length} repair(s) applied · file verified openable`;
    badgeText = "REPAIRED"; badgeClass = "rb-badge-green";
  } else if (repaired && !d.can_open) {
    bannerClass = "rb-warn";
    icon = "⚠️"; title = "Repairs Applied — Partial Recovery";
    sub  = "Structural repairs applied but file verification had issues. Download and test manually.";
    badgeText = "PARTIAL"; badgeClass = "rb-badge-amber";
  } else if (!hasCorrupt) {
    bannerClass = "rb-clean";
    icon = "✅"; title = "File Signature Intact — No Repair Needed";
    sub  = "All magic bytes match and structure appears valid.";
    badgeText = "CLEAN"; badgeClass = "rb-badge-green";
  } else {
    bannerClass = "rb-warn";
    icon = "⚠️"; title = "Corruption Detected";
    sub  = d.error || "See diagnosis below.";
    badgeText = "CORRUPT"; badgeClass = "rb-badge-red";
  }

  banner.className = "repair-banner " + bannerClass;
  document.getElementById("rbIcon").textContent  = icon;
  document.getElementById("rbTitle").textContent = title;
  document.getElementById("rbSub").textContent   = sub;
  const badge = document.getElementById("rbBadge");
  badge.textContent = badgeText;
  badge.className   = "rb-badge " + badgeClass;

  // ── Stats ────────────────────────────────────────────────────
  document.getElementById("rsc-name").textContent = d.original_name || "—";
  document.getElementById("rsc-type").textContent = d.file_type     || "—";
  document.getElementById("rsc-orig").textContent = fmtBytes(d.original_size || 0);
  document.getElementById("rsc-rep").textContent  = d.repair_success
    ? fmtBytes(d.repaired_size || 0) : "—";

  // ── Hex comparison ───────────────────────────────────────────
  document.getElementById("hexBefore").textContent   = d.hex_before   || "(empty)";
  document.getElementById("hexAfter").textContent    = d.hex_after    || "(same)";
  document.getElementById("hexExpected").textContent = d.expected_magic || "N/A";

  // Highlight changed bytes
  colorHexDiff("hexBefore", "hexAfter");

  // ── Corruption list ──────────────────────────────────────────
  const corrList = document.getElementById("corruptionList");
  const corr     = d.corruption_found || [];
  if (corr.length) {
    corrList.innerHTML = corr.map(c => {
      const isClean = /intact|valid|no corruption|found/i.test(c);
      return `<div class="diag-item ${isClean ? 'diag-ok' : 'diag-err'}">
        <span class="diag-icon">${isClean ? '✅' : '⚠️'}</span>
        <span class="diag-text">${escHtml(c)}</span>
      </div>`;
    }).join("");
  } else {
    corrList.innerHTML = `<div class="diag-item diag-ok"><span class="diag-icon">✅</span><span class="diag-text">No issues detected</span></div>`;
  }

  // ── Repairs list ─────────────────────────────────────────────
  const repList = (d.repairs_applied || []);
  const repCard = document.getElementById("repairsCard");
  if (repList.length) {
    repCard.style.display = "block";
    document.getElementById("repairsList").innerHTML = repList.map((r, i) =>
      `<div class="repair-item">
        <span class="ri-num">${i+1}</span>
        <span class="ri-text">${escHtml(r)}</span>
      </div>`
    ).join("");
  } else {
    repCard.style.display = "none";
  }

  // ── Download card ─────────────────────────────────────────────
  const dlCard = document.getElementById("repairDlCard");
  const noCard = document.getElementById("cannotRepairCard");
  if (repaired && (repairedB64 || repairDlUrl)) {
    dlCard.style.display = "block";
    noCard.style.display = "none";
    document.getElementById("repairDlSub").textContent =
      `Repaired size: ${fmtBytes(d.repaired_size || 0)} · ` +
      (d.can_open ? "Verified openable ✅" : "Structural repairs applied ⚠️");
  } else if (d.error || (!repaired && hasCorrupt)) {
    dlCard.style.display = "none";
    noCard.style.display = "block";
    document.getElementById("crSub").textContent =
      d.error || "The corruption is too severe for automatic repair. See guidance below.";
  } else {
    dlCard.style.display = "none";
    noCard.style.display = "none";
  }

  // ── Note / ffmpeg guidance ────────────────────────────────────
  const noteCard = document.getElementById("repairNoteCard");
  if (d.note) {
    noteCard.style.display = "block";
    document.getElementById("repairNoteText").textContent = d.note;
  } else {
    noteCard.style.display = "none";
  }

  setTimeout(() => sec.scrollIntoView({ behavior: "smooth", block: "start" }), 200);
}

// ── Download repaired file ────────────────────────────────────
function downloadRepaired() {
  const name = (selectedFile?.name ? "repaired_" + selectedFile.name : `repaired_file.${repairedExt}`);
  if (repairedB64) {
    // Decode base64 and trigger browser download
    const binary = atob(repairedB64);
    const bytes  = new Uint8Array(binary.length);
    for (let i = 0; i < binary.length; i++) bytes[i] = binary.charCodeAt(i);
    const blob = new Blob([bytes]);
    const url  = URL.createObjectURL(blob);
    const a    = document.createElement("a");
    a.href = url; a.download = name;
    document.body.appendChild(a); a.click();
    setTimeout(() => { URL.revokeObjectURL(url); a.remove(); }, 1000);
    toast("Download started!", "success");
  } else if (repairDlUrl) {
    window.location.href = repairDlUrl;
    toast("Downloading from server…", "info");
  } else {
    toast("No repaired file available.", "error");
  }
}

// ── Hex diff colouring ────────────────────────────────────────
function colorHexDiff(beforeId, afterId) {
  const before = document.getElementById(beforeId).textContent.trim().split(/\s+/);
  const after  = document.getElementById(afterId).textContent.trim().split(/\s+/);
  if (before.join("") === after.join("")) return; // no diff

  const colorByte = (byteArr, refArr, elId, highlight) => {
    const el = document.getElementById(elId);
    el.innerHTML = byteArr.map((b, i) => {
      const differs = b !== (refArr[i] || "??");
      return `<span style="${differs ? `color:${highlight};font-weight:700` : ''}">${escHtml(b)}</span>`;
    }).join(" ");
  };
  colorByte(before, after, beforeId, "#ef4444");
  colorByte(after,  before, afterId,  "#10b981");
}

// ── Helpers ───────────────────────────────────────────────────
function fmtBytes(b) {
  if (b < 1024)      return b + " B";
  if (b < 1048576)   return (b/1024).toFixed(1) + " KB";
  return (b/1048576).toFixed(1) + " MB";
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
(function () {
  const c = document.querySelector(".hero-grid");
  if (!c) return;
  const s = document.createElement("style");
  s.textContent = `@keyframes fp{0%,100%{opacity:.2;transform:translateY(0)}50%{opacity:.7;transform:translateY(-20px)}}`;
  document.head.appendChild(s);
  for (let i = 0; i < 25; i++) {
    const d = document.createElement("div"), sz = Math.random()*3+1;
    d.style.cssText = `position:absolute;width:${sz}px;height:${sz}px;background:rgba(0,210,211,${Math.random()*.4+.1});border-radius:50%;left:${Math.random()*100}%;top:${Math.random()*100}%;animation:fp ${Math.random()*8+5}s ease-in-out infinite;animation-delay:${Math.random()*5}s;pointer-events:none`;
    c.appendChild(d);
  }
})();

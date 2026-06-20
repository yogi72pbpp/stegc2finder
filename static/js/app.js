/* ═══════════════════════════════════════════════
   StegoDetect v2.0  —  app.js
   Multi-format file analyser frontend
═══════════════════════════════════════════════ */

const dropZone   = document.getElementById("dropZone");
const fileInput  = document.getElementById("fileInput");
const prevBar    = document.getElementById("previewBar");
const prevImg    = document.getElementById("previewImg");
const prevIconEl = document.getElementById("previewIcon");
const prevName   = document.getElementById("prevName");
const prevSize   = document.getElementById("prevSize");
const prevType   = document.getElementById("prevType");
const analyseBtn = document.getElementById("analyseBtn");

let selectedFile = null;

// ── File type map ─────────────────────────────────────────────
const FILE_ICONS = {
  image:  { icon: "🖼️", label: "Image",          color: "#00d2d3" },
  pdf:    { icon: "📄", label: "PDF Document",    color: "#ef4444" },
  office: { icon: "📝", label: "Office Document", color: "#3b82f6" },
  audio:  { icon: "🎵", label: "Audio File",      color: "#a855f7" },
  video:  { icon: "🎬", label: "Video File",      color: "#f59e0b" },
  apk:    { icon: "📦", label: "Android APK",     color: "#10b981" },
};

const IMAGE_EXTS  = new Set(["png","jpg","jpeg","bmp","gif","tiff","webp","ico","avif","svg"]);
const PDF_EXTS    = new Set(["pdf"]);
const OFFICE_EXTS = new Set(["doc","docx","odt","odf","ods","odp"]);
const AUDIO_EXTS  = new Set(["mp3","wav","flac","ogg","aac","m4a","wma"]);
const VIDEO_EXTS  = new Set(["mp4","avi","mkv","mov","wmv","flv","webm","3gp"]);
const APK_EXTS    = new Set(["apk"]);

function getFileCategory(filename) {
  const ext = filename.split(".").pop().toLowerCase();
  if (IMAGE_EXTS.has(ext))  return "image";
  if (PDF_EXTS.has(ext))    return "pdf";
  if (OFFICE_EXTS.has(ext)) return "office";
  if (AUDIO_EXTS.has(ext))  return "audio";
  if (VIDEO_EXTS.has(ext))  return "video";
  if (APK_EXTS.has(ext))    return "apk";
  return null;
}

// ── Drag & Drop ──────────────────────────────────────────────
["dragenter","dragover"].forEach(e =>
  dropZone.addEventListener(e, ev => { ev.preventDefault(); dropZone.classList.add("drag-over"); }));
["dragleave","drop"].forEach(e =>
  dropZone.addEventListener(e, ev => { ev.preventDefault(); dropZone.classList.remove("drag-over"); }));
dropZone.addEventListener("drop", e => { const f = e.dataTransfer.files[0]; if (f) handleFile(f); });
dropZone.addEventListener("click", () => fileInput.click());
fileInput.addEventListener("change", () => { if (fileInput.files[0]) handleFile(fileInput.files[0]); });

function handleFile(file) {
  const cat = getFileCategory(file.name);
  if (!cat) {
    toast("Unsupported file type. Use images, PDF, DOCX, ODF, audio, video, or APK.", "error");
    return;
  }
  if (file.size > 200 * 1024 * 1024) {
    toast("File too large. Maximum is 200 MB.", "error");
    return;
  }

  selectedFile = file;
  const meta   = FILE_ICONS[cat];

  // Update drop zone icon
  document.getElementById("dropIcon").textContent = meta.icon;

  // Image preview vs icon preview
  if (cat === "image") {
    prevImg.src             = URL.createObjectURL(file);
    prevImg.style.display   = "block";
    prevIconEl.style.display= "none";
  } else {
    prevImg.style.display   = "none";
    prevIconEl.style.display= "flex";
    prevIconEl.textContent  = meta.icon;
    prevIconEl.style.background = meta.color + "22";
    prevIconEl.style.color      = meta.color;
  }

  prevName.textContent      = file.name;
  prevSize.textContent      = fmtBytes(file.size);
  prevType.textContent      = meta.label;
  prevBar.style.display     = "flex";
  analyseBtn.disabled       = false;
  document.getElementById("resultsSection").style.display     = "none";
  document.getElementById("fileResultsSection").style.display = "none";
}

function clearFile() {
  selectedFile = null; fileInput.value = "";
  prevBar.style.display     = "none";
  analyseBtn.disabled       = true;
  document.getElementById("resultsSection").style.display     = "none";
  document.getElementById("fileResultsSection").style.display = "none";
  document.getElementById("dropIcon").textContent = "🖼️";
}

function reset() { clearFile(); window.scrollTo({ top: 0, behavior: "smooth" }); }

// ── Run Analysis ─────────────────────────────────────────────
async function runAnalysis() {
  if (!selectedFile) return;

  const cat     = getFileCategory(selectedFile.name);
  const overlay = document.getElementById("loadingOverlay");
  const title   = document.getElementById("loadingTitle");

  if (cat === "image") {
    title.textContent = "Analysing with NumPy + OpenCV...";
  } else {
    title.textContent = `Analysing ${FILE_ICONS[cat]?.label || "file"}...`;
  }

  overlay.style.display = "flex";

  const steps = ["st1","st2","st3","st4","st5","st6"];
  steps.forEach(s => document.getElementById(s)?.classList.remove("active","done"));
  let idx = 0;
  const timer = setInterval(() => {
    if (idx > 0) document.getElementById(steps[idx-1])?.classList.replace("active","done");
    if (idx < steps.length) { document.getElementById(steps[idx])?.classList.add("active"); idx++; }
  }, 400);

  const form = new FormData();
  form.append("image", selectedFile);   // backend accepts both "image" and "file"

  try {
    const res  = await fetch("/analyse", { method: "POST", body: form });
    const data = await res.json();
    clearInterval(timer);
    steps.forEach(s => document.getElementById(s)?.classList.add("done"));
    await sleep(300);
    overlay.style.display = "none";

    if (data.error) { toast("Error: " + data.error, "error"); return; }

    if (data.file_type === "image") {
      renderResults(data);
    } else {
      renderFileResults(data);
    }
  } catch (err) {
    clearInterval(timer);
    overlay.style.display = "none";
    toast("Network error. Is the server running?", "error");
  }
}

// ── Render Image Results ─────────────────────────────────────
function renderResults(d) {
  const sec = document.getElementById("resultsSection");
  sec.style.display = "block";
  document.getElementById("fileResultsSection").style.display = "none";

  const banner = document.getElementById("resultBanner");
  banner.className = "result-banner " + (d.is_stego ? "stego" : "normal");
  document.getElementById("ri").textContent = d.is_stego ? "⚠️" : "✅";
  document.getElementById("rl").textContent = d.is_stego
    ? "Steganographic Image Detected"
    : "Normal Image — No Hidden Data Found";
  document.getElementById("rd").textContent = d.is_stego
    ? `Hidden data detected with ${d.confidence}% confidence. Statistical anomalies found in multi-scale noise residual.`
    : `Image appears clean with ${d.confidence}% confidence. No significant steganographic signal detected.`;

  const circumference = 2 * Math.PI * 50;
  const offset = circumference - (d.confidence / 100) * circumference;
  setTimeout(() => { document.getElementById("cp").style.strokeDashoffset = offset; }, 100);
  document.getElementById("confVal").textContent = d.confidence.toFixed(1) + "%";

  document.getElementById("sc-file").textContent   = d.filename;
  document.getElementById("sc-dims").textContent   = d.dimensions;
  document.getElementById("sc-time").textContent   = d.proc_time_ms + " ms";
  document.getElementById("sc-engine").textContent = d.engine || "RandomForest";

  document.getElementById("origImg").src  = "data:image/png;base64," + d.image_b64;
  document.getElementById("residImg").src = "data:image/png;base64," + d.residual_b64;

  setTimeout(() => {
    document.getElementById("pNorm").style.width  = d.confidence_normal + "%";
    document.getElementById("pStego").style.width = d.confidence_stego  + "%";
  }, 300);
  document.getElementById("pNormPct").textContent  = d.confidence_normal.toFixed(1) + "%";
  document.getElementById("pStegoPct").textContent = d.confidence_stego.toFixed(1)  + "%";

  const htCard = document.getElementById("hiddenCard");
  if (d.text_found && d.hidden_text) {
    htCard.style.display = "block";
    document.getElementById("htBox").textContent   = d.hidden_text;
    document.getElementById("htBadge").textContent = d.text_length + " characters";
  } else {
    htCard.style.display = "none";
  }

  const grid = document.getElementById("featGrid");
  grid.innerHTML = "";
  d.features.forEach(f => {
    const el = document.createElement("div");
    el.className = "fi";
    el.innerHTML = `<div class="fn">${f.name}</div><div class="fv">${f.value}</div>`;
    grid.appendChild(el);
  });

  setTimeout(() => sec.scrollIntoView({ behavior: "smooth", block: "start" }), 200);
}

// ── Render Non-Image File Results ────────────────────────────
function renderFileResults(d) {
  const sec = document.getElementById("fileResultsSection");
  sec.style.display = "block";
  document.getElementById("resultsSection").style.display = "none";

  const cat  = d.file_type;
  const meta = FILE_ICONS[cat] || { icon: "📁", label: cat.toUpperCase(), color: "#94a3b8" };
  const a    = d.analysis || {};
  const suspicious = a.suspicious || false;

  // Banner
  const banner = document.getElementById("fileResultBanner");
  banner.className = "file-result-banner " + (suspicious ? "suspicious" : "clean");
  document.getElementById("frbIcon").textContent  = suspicious ? "⚠️" : meta.icon;
  document.getElementById("frbTitle").textContent = suspicious
    ? `${meta.label} — Suspicious Content Detected`
    : `${meta.label} — Analysis Complete`;
  document.getElementById("frbSub").textContent   = suspicious
    ? (a.suspicious_reasons || []).join("; ")
    : `File analysed successfully. No immediate threats detected.`;
  const badge = document.getElementById("frbBadge");
  badge.textContent  = suspicious ? "SUSPICIOUS" : "CLEAN";
  badge.className    = "frb-badge " + (suspicious ? "badge-red" : "badge-green");

  // Stats
  document.getElementById("fsc-file").textContent = d.filename;
  document.getElementById("fsc-type").textContent = meta.label;
  document.getElementById("fsc-size").textContent = fmtBytes(selectedFile?.size || 0);
  document.getElementById("fsc-time").textContent = d.proc_time_ms + " ms";

  // Details card content
  const body  = document.getElementById("fileDetailsBody");
  const title = document.getElementById("fileDetailsTitle");
  body.innerHTML = "";

  if (cat === "pdf") {
    title.textContent = "📄 PDF Document Details";
    body.innerHTML = buildDetailGrid([
      { label: "Pages",           value: a.pages || "N/A" },
      { label: "File Size",       value: (a.file_size_kb || 0) + " KB" },
      { label: "Has JavaScript",  value: a.has_javascript ? "⚠️ Yes" : "✅ No" },
      { label: "Embedded Files",  value: a.has_embedded_files ? "⚠️ Yes" : "✅ No" },
      ...Object.entries(a.metadata || {}).map(([k,v]) => ({ label: k, value: v }))
    ]);
    if (a.text_preview) {
      body.innerHTML += `<div class="text-preview-block"><div class="tpb-title">Text Preview</div><div class="tpb-content">${escHtml(a.text_preview)}</div></div>`;
    }
  } else if (cat === "office") {
    title.textContent = "📝 Document Details";
    body.innerHTML = buildDetailGrid([
      { label: "Format",      value: a.type || "Office" },
      { label: "File Size",   value: (a.file_size_kb || 0) + " KB" },
      { label: "Has Macros",  value: a.has_macros ? "⚠️ Yes (VBA)" : "✅ No" },
      { label: "Ext. Links",  value: (a.external_links || []).length || 0 },
      ...Object.entries(a.metadata || {}).map(([k,v]) => ({ label: k, value: v }))
    ]);
    if (a.text_preview) {
      body.innerHTML += `<div class="text-preview-block"><div class="tpb-title">Text Preview</div><div class="tpb-content">${escHtml(a.text_preview)}</div></div>`;
    }
  } else if (cat === "audio") {
    title.textContent = "🎵 Audio File Details";
    body.innerHTML = buildDetailGrid([
      { label: "Format",      value: a.type || "Audio" },
      { label: "Duration",    value: a.duration_sec ? a.duration_sec + "s" : "N/A" },
      { label: "Sample Rate", value: a.sample_rate ? a.sample_rate + " Hz" : "N/A" },
      { label: "Channels",    value: a.channels || "N/A" },
      { label: "Bit Depth",   value: a.bit_depth ? a.bit_depth + "-bit" : "N/A" },
      { label: "File Size",   value: (a.file_size_kb || 0) + " KB" },
      ...Object.entries(a.metadata || {}).map(([k,v]) => ({ label: k, value: v }))
    ]);
  } else if (cat === "video") {
    title.textContent = "🎬 Video File Details";
    body.innerHTML = buildDetailGrid([
      { label: "Format",      value: a.type || "Video" },
      { label: "Resolution",  value: a.resolution || "N/A" },
      { label: "Duration",    value: a.duration_sec ? a.duration_sec + "s" : "N/A" },
      { label: "FPS",         value: a.fps || "N/A" },
      { label: "Frames",      value: a.frame_count || "N/A" },
      { label: "File Size",   value: (a.file_size_kb || 0) + " KB" },
    ]);
    if (a.frame_analysis && a.frame_analysis.length) {
      let tbl = `<div style="margin-top:.9rem"><div class="tpb-title">Frame Stego Analysis (Sampled)</div><table class="c2-table" style="margin-top:.4rem"><thead><tr><th>Frame #</th><th>Result</th><th>Confidence</th></tr></thead><tbody>`;
      a.frame_analysis.forEach(f => {
        tbl += `<tr><td>#${f.frame}</td><td>${f.is_stego ? '<span style="color:var(--red)">⚠️ Stego</span>' : '<span style="color:var(--green)">✅ Clean</span>'}</td><td>${f.confidence}%</td></tr>`;
      });
      tbl += `</tbody></table></div>`;
      body.innerHTML += tbl;
    }
  } else if (cat === "apk") {
    title.textContent = "📦 APK Quick Scan";
    body.innerHTML = buildDetailGrid([
      { label: "Package",   value: a.package_name || "Unknown" },
      { label: "File Size", value: (a.file_size_kb || 0) + " KB" },
      { label: "DEX Files", value: a.dex_count || 0 },
      { label: "Files",     value: a.file_count || 0 },
    ]);
    document.getElementById("apkHintCard").style.display = "block";
  }

  // Suspicious findings
  const sus = a.suspicious_reasons || [];
  if (sus.length) {
    const susCard = document.getElementById("susFindingsCard");
    susCard.style.display = "block";
    const list = document.getElementById("susFindingsList");
    list.innerHTML = sus.map(r => `<div class="sus-item">⚠️ ${escHtml(r)}</div>`).join("");
  } else {
    document.getElementById("susFindingsCard").style.display = "none";
  }

  if (cat !== "apk") {
    document.getElementById("apkHintCard").style.display = "none";
  }

  setTimeout(() => sec.scrollIntoView({ behavior: "smooth", block: "start" }), 200);
}

// ── Build detail grid HTML ────────────────────────────────────
function buildDetailGrid(items) {
  return `<div class="detail-grid">${
    items.filter(i => i.value !== undefined && i.value !== null && i.value !== "")
         .map(i => `<div class="dg-item"><div class="dg-label">${escHtml(String(i.label))}</div><div class="dg-value">${escHtml(String(i.value))}</div></div>`)
         .join("")
  }</div>`;
}

// ── Copy hidden text ──────────────────────────────────────────
function copyText() {
  const txt = document.getElementById("htBox").textContent;
  navigator.clipboard.writeText(txt)
    .then(() => toast("Copied to clipboard!", "success"))
    .catch(() => toast("Select text manually and copy.", "info"));
}

// ── Helpers ───────────────────────────────────────────────────
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

// ── Particle background ───────────────────────────────────────
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

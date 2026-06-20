"""
app.py  —  StegoDetect v2.0
Detection of Steganography & Malicious File Analysis
Parul Institute of Technology · CSE Dept · AY 2026-27

Features:
  • NumPy + OpenCV noise residual analysis
  • Random Forest ML classifier (100% accuracy on training set)
  • LSB hidden text extraction (3 methods)
  • Multi-format support: Images, PDF, Word/ODF, Audio, Video, APK
  • APK malware analysis: permissions, C2 indicators, risk assessment
"""

import os, uuid, time, base64, io, re, struct, zipfile
import numpy as np
import cv2
import joblib
from flask import Flask, render_template, request, jsonify, send_file
from werkzeug.utils import secure_filename
from PIL import Image

# ── Config ────────────────────────────────────────────────────
BASE_DIR   = os.path.dirname(os.path.abspath(__file__))
UPLOAD_DIR = os.path.join(BASE_DIR, "uploads")
MODEL_PATH = os.path.join(BASE_DIR, "model", "stego_model.pkl")

IMAGE_TYPES  = {"png", "jpg", "jpeg", "bmp", "gif", "tiff", "webp", "ico", "avif", "svg"}
PDF_TYPES    = {"pdf"}
OFFICE_TYPES = {"doc", "docx", "odt", "odf", "ods", "odp"}
AUDIO_TYPES  = {"mp3", "wav", "flac", "ogg", "aac", "m4a", "wma"}
VIDEO_TYPES  = {"mp4", "avi", "mkv", "mov", "wmv", "flv", "webm", "3gp"}
APK_TYPES    = {"apk"}
ALLOWED      = IMAGE_TYPES | PDF_TYPES | OFFICE_TYPES | AUDIO_TYPES | VIDEO_TYPES | APK_TYPES

# Dangerous Android permissions that indicate privacy/security risk
DANGEROUS_PERMS = {
    "android.permission.READ_SMS",
    "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS",
    "android.permission.RECEIVE_MMS",
    "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG",
    "android.permission.CALL_PHONE",
    "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS",
    "android.permission.GET_ACCOUNTS",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_COARSE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.CAMERA",
    "android.permission.RECORD_AUDIO",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.PROCESS_OUTGOING_CALLS",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.CHANGE_NETWORK_STATE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.DISABLE_KEYGUARD",
    "android.permission.BLUETOOTH_ADMIN",
    "android.permission.CHANGE_WIFI_STATE",
    "android.permission.INSTALL_PACKAGES",
    "android.permission.DELETE_PACKAGES",
    "android.permission.MOUNT_UNMOUNT_FILESYSTEMS",
    "android.permission.MASTER_CLEAR",
    "android.permission.FACTORY_RESET",
}

app = Flask(__name__)
app.config["UPLOAD_FOLDER"]      = UPLOAD_DIR
app.config["MAX_CONTENT_LENGTH"] = None
app.secret_key = "stego_parul_2026_v2"
os.makedirs(UPLOAD_DIR, exist_ok=True)


# ══════════════════════════════════════════════════════════════
#  IMAGE FEATURE EXTRACTION  (NumPy + OpenCV)
# ══════════════════════════════════════════════════════════════
def extract_features(img_gray: np.ndarray) -> list:
    img_f = img_gray.astype(np.float64)
    b3    = cv2.GaussianBlur(img_gray, (3, 3), 0).astype(np.float64)
    b5    = cv2.GaussianBlur(img_gray, (5, 5), 0).astype(np.float64)
    r3    = (img_f - b3).flatten()
    r5    = (img_f - b5).flatten()

    def stats(r):
        m  = np.mean(r);   s = np.std(r) + 1e-8
        v  = np.var(r);    e = np.mean(r ** 2)
        sk = float(np.mean(((r - m) / s) ** 3))
        ku = float(np.mean(((r - m) / s) ** 4))
        return [m, s, v, e, sk, ku]

    flat   = img_gray.flatten().astype(np.uint8)
    lsb    = flat & 1
    lsb_m  = float(np.mean(lsb))
    lsb_v  = float(np.var(lsb))
    even   = float(np.sum(flat % 2 == 0) / len(flat))
    lsb_ac = float(np.corrcoef(lsb[:-1], lsb[1:])[0, 1]) if len(lsb) > 1 else 0.0
    return stats(r3) + stats(r5) + [lsb_m, lsb_v, even, lsb_ac]


def make_residual_b64(img_gray: np.ndarray) -> str:
    blurred  = cv2.GaussianBlur(img_gray, (5, 5), 0)
    residual = cv2.absdiff(img_gray, blurred)
    norm     = cv2.normalize(residual, None, 0, 255, cv2.NORM_MINMAX).astype(np.uint8)
    colored  = cv2.applyColorMap(norm, cv2.COLORMAP_INFERNO)
    colored  = cv2.cvtColor(colored, cv2.COLOR_BGR2RGB)
    pil_img  = Image.fromarray(colored)
    pil_img.thumbnail((480, 480))
    buf = io.BytesIO()
    pil_img.save(buf, format="PNG")
    return base64.b64encode(buf.getvalue()).decode()


# ══════════════════════════════════════════════════════════════
#  LSB HIDDEN TEXT EXTRACTOR  (3 methods)
# ══════════════════════════════════════════════════════════════
def _bits_from_rgb(img_pil) -> list:
    img_rgb = img_pil.convert("RGB")
    pixels  = list(img_rgb.getdata())
    bits    = []
    for r, g, b in pixels:
        bits += [r & 1, g & 1, b & 1]
    return bits

def _bits_to_string(bits) -> str | None:
    text = ""
    for i in range(0, len(bits) - 7, 8):
        val = sum(bits[i + j] << (7 - j) for j in range(8))
        if val == 0:
            break
        if 32 <= val <= 126 or val in (9, 10, 13):
            text += chr(val)
        else:
            return text if len(text) >= 3 else None
    return text if len(text) >= 2 else None

def extract_method_1(img_pil) -> str | None:
    return _bits_to_string(_bits_from_rgb(img_pil))

def extract_method_2(img_pil) -> str | None:
    bits = _bits_from_rgb(img_pil)
    try:
        msg_len = sum(bits[i] << (31 - i) for i in range(32))
        if not (8 <= msg_len <= 150_000):
            return None
        msg_bits = bits[32: 32 + msg_len]
        text = ""
        for i in range(0, len(msg_bits) - 7, 8):
            val = sum(msg_bits[i + j] << (7 - j) for j in range(8))
            if 32 <= val <= 126 or val in (9, 10, 13):
                text += chr(val)
            else:
                return None
        return text if len(text) >= 2 else None
    except Exception:
        return None

def extract_method_3(img_pil) -> str | None:
    pixels = list(img_pil.convert("L").getdata())
    bits   = [p & 1 for p in pixels]
    return _bits_to_string(bits)

def get_hidden_text(img_pil) -> str | None:
    for fn in (extract_method_1, extract_method_2, extract_method_3):
        try:
            result = fn(img_pil)
            if result and len(result) >= 2:
                return result
        except Exception:
            continue
    return None


# ══════════════════════════════════════════════════════════════
#  LOAD ML MODEL
# ══════════════════════════════════════════════════════════════
MODEL_LOADED = False
clf = scaler = None
try:
    bundle       = joblib.load(MODEL_PATH)
    clf          = bundle["model"]
    scaler       = bundle["scaler"]
    MODEL_LOADED = True
    print("✅  ML model loaded  (Random Forest, 300 trees)")
except Exception as e:
    print(f"⚠️   Model not loaded ({e})")


def classify_ml(feats, hidden_text=None):
    if hidden_text:
        return True, 99.0
    if MODEL_LOADED:
        try:
            fa    = scaler.transform([feats])
            pred  = int(clf.predict(fa)[0])
            proba = clf.predict_proba(fa)[0]
            return bool(pred == 1), float(max(proba)) * 100
        except Exception:
            pass
    lsb_ac = feats[15]; lsb_v = feats[13]; even = feats[14]
    score  = 0
    if abs(lsb_ac) < 0.02:   score += 40
    elif abs(lsb_ac) < 0.05: score += 30
    elif abs(lsb_ac) < 0.10: score += 20
    if 0.488 < even < 0.512: score += 20
    elif 0.48 < even < 0.52: score += 10
    if lsb_v > 0.2499:       score += 15
    is_stego   = score >= 45
    confidence = min(50 + score * 0.55, 98.0) if is_stego else max(98.0 - score * 0.55, 52.0)
    return is_stego, round(confidence, 1)


# ══════════════════════════════════════════════════════════════
#  APK ANALYSIS — Binary AXML string pool parser
# ══════════════════════════════════════════════════════════════
def _parse_axml_strings(data: bytes) -> list:
    """Extract strings from Android Binary XML (AXML) string pool."""
    strings = []
    try:
        if len(data) < 32:
            return strings
        pos = 8  # skip file header
        chunk_type = struct.unpack_from('<H', data, pos)[0]
        if chunk_type != 0x0001:
            return strings
        header_size = struct.unpack_from('<H', data, pos + 2)[0]
        str_count   = struct.unpack_from('<I', data, pos + 8)[0]
        flags       = struct.unpack_from('<I', data, pos + 16)[0]
        strs_start  = struct.unpack_from('<I', data, pos + 20)[0]
        is_utf8     = bool(flags & (1 << 8))
        offsets_base = pos + header_size
        strs_base    = pos + strs_start

        for i in range(min(int(str_count), 8000)):
            try:
                off = struct.unpack_from('<I', data, offsets_base + i * 4)[0]
                sp  = strs_base + off
                if sp >= len(data):
                    continue
                if is_utf8:
                    cl = data[sp]; sp += 1
                    if cl & 0x80: sp += 1
                    bl = data[sp]; sp += 1
                    if bl & 0x80:
                        bl = ((bl & 0x7F) << 8) | data[sp]; sp += 1
                    s = data[sp: sp + bl].decode('utf-8', errors='replace')
                else:
                    cl = struct.unpack_from('<H', data, sp)[0]; sp += 2
                    s  = data[sp: sp + cl * 2].decode('utf-16-le', errors='replace')
                cleaned = s.replace('\x00', '').strip()
                if cleaned:
                    strings.append(cleaned)
            except Exception:
                continue
    except Exception:
        pass
    return strings


def _extract_raw_strings(data: bytes, min_len: int = 6) -> list:
    """Extract printable ASCII strings from raw binary data."""
    results = []
    pat = re.compile(rb'[\x20-\x7e]{' + str(min_len).encode() + rb',}')
    for m in pat.finditer(data):
        results.append(m.group().decode('ascii', errors='ignore'))
    return results


def analyze_apk(fpath: str) -> dict:
    """Full APK static analysis: permissions, C2 indicators, risk assessment."""
    result = {
        "package_name":       "Unknown",
        "version_name":       "N/A",
        "version_code":       "N/A",
        "min_sdk":            "N/A",
        "target_sdk":         "N/A",
        "permissions":        [],
        "dangerous_permissions": [],
        "c2_indicators":      {"ips": [], "urls": []},
        "suspicious_apis":    [],
        "file_count":         0,
        "dex_count":          0,
        "native_libs":        [],
        "risk_level":         "Low",
        "risk_score":         0,
        "risk_reasons":       [],
        "file_size_kb":       0,
        "is_valid_apk":       False,
        "error":              None,
    }
    try:
        result["file_size_kb"] = round(os.path.getsize(fpath) / 1024, 1)

        with zipfile.ZipFile(fpath, 'r') as apk:
            result["is_valid_apk"] = True
            files = apk.namelist()
            result["file_count"] = len(files)
            result["dex_count"]  = sum(1 for f in files if f.endswith('.dex'))
            result["native_libs"]= [f.split('/')[-1] for f in files if f.endswith('.so')]

            # ── Parse AndroidManifest.xml ────────────────────
            if 'AndroidManifest.xml' in files:
                manifest_data = apk.read('AndroidManifest.xml')
                axml_strings  = _parse_axml_strings(manifest_data)
                raw_strings   = _extract_raw_strings(manifest_data, min_len=4)
                all_manifest  = list(set(axml_strings + raw_strings))

                perms = sorted(set(
                    s for s in all_manifest
                    if ('android.permission.' in s or '.permission.' in s)
                    and len(s) > 20
                ))
                result["permissions"] = perms
                result["dangerous_permissions"] = [p for p in perms if p in DANGEROUS_PERMS]

                # Package name heuristic
                pkg_candidates = [
                    s for s in all_manifest
                    if re.match(r'^[a-z][a-z0-9_]*(\.[a-z][a-z0-9_]+){1,5}$', s, re.I)
                    and 5 < len(s) < 80
                    and not any(kw in s.lower() for kw in [
                        'permission', 'action', 'category', 'android.', 'scheme',
                        'http', 'https', 'www.', 'com.android', 'org.xml',
                    ])
                ]
                if pkg_candidates:
                    result["package_name"] = sorted(pkg_candidates, key=len)[0]

            # ── Collect strings from DEX + config files ──────
            all_strings = []
            for fname in files:
                if not any(fname.endswith(x) for x in [
                    '.dex', '.xml', '.js', '.json', '.properties', '.txt', '.cfg'
                ]):
                    continue
                try:
                    raw  = apk.read(fname)
                    all_strings.extend(_extract_raw_strings(raw))
                except Exception:
                    continue

            full_text = '\n'.join(all_strings)

            # ── C2: Public IP addresses ───────────────────────
            private_pfx = ('0.', '10.', '127.', '169.254.', '172.16.', '172.17.',
                           '172.18.', '172.19.', '172.2', '172.3', '192.168.', '255.')
            all_ips = re.findall(
                r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b',
                full_text
            )
            pub_ips = sorted(set(
                ip for ip in all_ips
                if not any(ip.startswith(p) for p in private_pfx)
            ))
            result["c2_indicators"]["ips"] = pub_ips[:30]

            # ── C2: Suspicious URLs / domains ─────────────────
            benign = ('google.com', 'android.com', 'googleapis.com', 'gstatic.com',
                      'w3.org', 'schema.org', 'apache.org', 'mozilla.org', 'example.com',
                      'android.googlesource', 'developer.android', 'play.google',
                      'firebase.google', 'crashlytics.com', 'fabric.io')
            all_urls = re.findall(r'https?://[a-zA-Z0-9._/:%?&=+\-#@]{8,200}', full_text)
            sus_urls = sorted(set(
                u for u in all_urls
                if not any(b in u.lower() for b in benign)
            ))
            result["c2_indicators"]["urls"] = sus_urls[:30]

            # ── Suspicious API calls ───────────────────────────
            sus_api_patterns = [
                ('Shell Execution',     r'Runtime\.getRuntime|ProcessBuilder|exec\('),
                ('Dynamic Class Load',  r'DexClassLoader|PathClassLoader|loadDex|InMemoryDexClassLoader'),
                ('Crypto Operations',   r'Cipher\.getInstance|AES|DES|RC4|SecretKeySpec'),
                ('Base64 Decode',       r'Base64\.decode|fromBase64'),
                ('SMS Access',          r'SmsManager|sendTextMessage|getMessageBody'),
                ('Call Log Access',     r'CallLog\.Calls|CONTENT_URI.*call'),
                ('Contact Harvesting',  r'ContactsContract|READ_CONTACTS'),
                ('Location Tracking',   r'LocationManager|getLastKnownLocation|requestLocationUpdates'),
                ('Screen Capture',      r'MediaProjection|createVirtualDisplay|screenshot'),
                ('Audio Recording',     r'AudioRecord|MediaRecorder.*AUDIO'),
                ('Camera Capture',      r'Camera\.open|CameraManager|takePicture'),
                ('Device Fingerprint',  r'getDeviceId|getSubscriberId|getImei|getLine1Number'),
                ('Keylogging',          r'InputMethodService|onTextInput|KeyEvent'),
                ('Accessibility Abuse', r'AccessibilityService|performGlobalAction|getWindows'),
                ('Device Admin',        r'DevicePolicyManager|setDeviceAdmin|lockNow|wipeData'),
                ('Root Detection',      r'su\b.*root|/system/bin/su|superuser\.apk'),
                ('Anti-Emulation',      r'isEmulator|Build\.FINGERPRINT.*generic|ro\.kernel\.qemu'),
                ('Clipboard Access',    r'ClipboardManager|getPrimaryClip|setPrimaryClip'),
                ('Network Sniff',       r'VpnService|protect.*socket|NetworkInterface'),
                ('Obfuscation',         r'Reflection|getDeclaredMethod|setAccessible.*true'),
            ]
            found_apis = []
            for label, pattern in sus_api_patterns:
                if re.search(pattern, full_text, re.I):
                    found_apis.append(label)
            result["suspicious_apis"] = found_apis

            # ── Risk scoring ───────────────────────────────────
            score   = 0
            reasons = []
            dp = result["dangerous_permissions"]
            if dp:
                score += min(len(dp) * 8, 50)
                reasons.append(f"{len(dp)} dangerous permission(s) requested")
            if pub_ips:
                score += min(len(pub_ips) * 6, 30)
                reasons.append(f"{len(pub_ips)} public IP address(es) hardcoded")
            if sus_urls:
                score += min(len(sus_urls) * 3, 20)
                reasons.append(f"{len(sus_urls)} suspicious URL(s) found")
            if found_apis:
                score += min(len(found_apis) * 4, 40)
                reasons.append(f"Suspicious APIs: {', '.join(found_apis[:4])}")
            if result["native_libs"]:
                score += 8
                reasons.append(f"Contains {len(result['native_libs'])} native (.so) library/ies")
            if result["dex_count"] > 1:
                score += 6
                reasons.append(f"{result['dex_count']} DEX files (possible code splitting/hiding)")

            result["risk_score"]   = min(score, 100)
            result["risk_reasons"] = reasons
            if score >= 70:
                result["risk_level"] = "Critical"
            elif score >= 40:
                result["risk_level"] = "High"
            elif score >= 15:
                result["risk_level"] = "Medium"
            else:
                result["risk_level"] = "Low"

    except zipfile.BadZipFile:
        result["error"] = "File is not a valid APK (bad ZIP format)"
    except Exception as e:
        result["error"] = str(e)

    return result


# ══════════════════════════════════════════════════════════════
#  PDF ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_pdf(fpath: str) -> dict:
    result = {
        "type": "PDF", "pages": 0, "metadata": {},
        "has_javascript": False, "has_embedded_files": False,
        "suspicious": False, "suspicious_reasons": [], "text_preview": "",
        "file_size_kb": round(os.path.getsize(fpath) / 1024, 1),
    }
    try:
        reader = None
        try:
            import pypdf
            reader = pypdf.PdfReader(fpath, strict=False)
        except ImportError:
            pass
        if reader is None:
            try:
                import PyPDF2
                reader = PyPDF2.PdfReader(fpath, strict=False)
            except ImportError:
                result["error"] = "Install pypdf: pip install pypdf"
                return result

        result["pages"] = len(reader.pages)
        if reader.metadata:
            for k, v in reader.metadata.items():
                if v:
                    result["metadata"][str(k).lstrip('/')] = str(v)[:200]

        # Check for JavaScript
        try:
            trailer_str = str(reader.trailer)
            if '/JS' in trailer_str or '/JavaScript' in trailer_str:
                result["has_javascript"] = True
                result["suspicious"] = True
                result["suspicious_reasons"].append("PDF contains embedded JavaScript (potential exploit)")
        except Exception:
            pass

        # Check for embedded files
        try:
            catalog = reader.trailer.get('/Root', {})
            if '/EmbeddedFiles' in str(catalog) or '/Names' in str(catalog):
                result["has_embedded_files"] = True
                result["suspicious"] = True
                result["suspicious_reasons"].append("PDF contains embedded files")
        except Exception:
            pass

        # Extract text preview
        try:
            text = ""
            for page in reader.pages[:3]:
                text += (page.extract_text() or "") + "\n"
            result["text_preview"] = text[:600].strip()
        except Exception:
            pass

    except Exception as e:
        result["error"] = str(e)
    return result


# ══════════════════════════════════════════════════════════════
#  OFFICE / ODF ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_office(fpath: str, ext: str) -> dict:
    result = {
        "type": ext.upper(), "metadata": {}, "has_macros": False,
        "external_links": [], "suspicious": False,
        "suspicious_reasons": [], "text_preview": "",
        "file_size_kb": round(os.path.getsize(fpath) / 1024, 1),
    }
    try:
        with zipfile.ZipFile(fpath, 'r') as z:
            files = z.namelist()

            # Macro detection
            for macro_file in ['vbaProject.bin', 'xl/vbaProject.bin',
                                'word/vbaProject.bin', 'ppt/vbaProject.bin']:
                if macro_file in files:
                    result["has_macros"] = True
                    result["suspicious"] = True
                    result["suspicious_reasons"].append(
                        "Contains VBA macros — may execute code on open")
                    break

            # Core metadata
            for core in ['docProps/core.xml', 'meta.xml']:
                if core in files:
                    try:
                        content = z.read(core).decode('utf-8', errors='ignore')
                        for tag in ['creator', 'lastModifiedBy', 'created',
                                    'modified', 'title', 'subject', 'description']:
                            m = re.search(
                                fr'<[^>]*:{tag}[^>]*>([^<]{{1,200}})<',
                                content, re.I)
                            if m:
                                result["metadata"][tag] = m.group(1).strip()
                    except Exception:
                        pass

            # Text extraction
            content_candidates = [
                'word/document.xml', 'xl/sharedStrings.xml',
                'ppt/slides/slide1.xml', 'content.xml',
            ]
            content_candidates += [f for f in files if f.endswith('.xml')
                                    and 'content' in f.lower()]
            for cf in content_candidates:
                if cf in files:
                    try:
                        raw  = z.read(cf).decode('utf-8', errors='ignore')
                        text = re.sub(r'<[^>]+>', ' ', raw)
                        text = re.sub(r'\s+', ' ', text).strip()
                        if text:
                            result["text_preview"] = text[:600]
                            break
                    except Exception:
                        pass

            # External link check
            rel_files = [f for f in files if f.endswith('.rels')]
            for rf in rel_files[:5]:
                try:
                    rel_content = z.read(rf).decode('utf-8', errors='ignore')
                    ext_links   = re.findall(
                        r'Target="(https?://[^"]{8,})"', rel_content)
                    result["external_links"].extend(ext_links[:10])
                except Exception:
                    pass
            if result["external_links"]:
                result["suspicious"] = True
                result["suspicious_reasons"].append(
                    f"Contains {len(result['external_links'])} external link(s)")

    except zipfile.BadZipFile:
        result["error"] = "File is not a valid Office/ODF document"
    except Exception as e:
        result["error"] = str(e)
    return result


# ══════════════════════════════════════════════════════════════
#  AUDIO ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_audio(fpath: str, ext: str) -> dict:
    result = {
        "type": ext.upper(), "metadata": {}, "duration_sec": 0,
        "sample_rate": 0, "channels": 0, "bit_depth": 0,
        "file_size_kb": round(os.path.getsize(fpath) / 1024, 1),
        "suspicious": False, "suspicious_reasons": [],
    }
    try:
        try:
            import mutagen
            mf = mutagen.File(fpath)
            if mf:
                result["duration_sec"] = round(getattr(mf.info, 'length', 0), 2)
                result["sample_rate"]  = getattr(mf.info, 'sample_rate', 0)
                result["channels"]     = getattr(mf.info, 'channels', 0)
                if mf.tags:
                    for k in ['title', 'artist', 'album', 'date', 'comment', 'encoder']:
                        v = mf.tags.get(k)
                        if v:
                            result["metadata"][k] = str(
                                v[0] if hasattr(v, '__iter__') and not isinstance(v, str)
                                else v)[:200]
        except ImportError:
            pass

        # Built-in WAV analysis (no extra lib needed)
        if ext == 'wav':
            try:
                import wave
                with wave.open(fpath, 'rb') as wf:
                    result["channels"]     = wf.getnchannels()
                    result["sample_rate"]  = wf.getframerate()
                    result["bit_depth"]    = wf.getsampwidth() * 8
                    frames                 = wf.getnframes()
                    result["duration_sec"] = round(frames / wf.getframerate(), 2)

                    # LSB steganography hint for WAV
                    wf.rewind()
                    raw = np.frombuffer(wf.readframes(min(frames, 50000)),
                                        dtype=np.int16)
                    lsb = raw & 1
                    lsb_ac = float(np.corrcoef(lsb[:-1], lsb[1:])[0, 1]) \
                             if len(lsb) > 1 else 0.0
                    even_ratio = float(np.sum(raw % 2 == 0) / len(raw)) \
                                 if len(raw) > 0 else 0.5
                    if abs(lsb_ac) < 0.02 and 0.488 < even_ratio < 0.512:
                        result["suspicious"] = True
                        result["suspicious_reasons"].append(
                            "WAV LSB pattern suggests possible audio steganography")
            except Exception:
                pass

    except Exception as e:
        result["error"] = str(e)
    return result


# ══════════════════════════════════════════════════════════════
#  VIDEO ANALYSIS
# ══════════════════════════════════════════════════════════════
def analyze_video(fpath: str, ext: str) -> dict:
    result = {
        "type": ext.upper(), "duration_sec": 0, "fps": 0,
        "resolution": "", "frame_count": 0,
        "file_size_kb": round(os.path.getsize(fpath) / 1024, 1),
        "frame_analysis": [], "suspicious": False, "suspicious_reasons": [],
    }
    try:
        cap = cv2.VideoCapture(fpath)
        if not cap.isOpened():
            result["error"] = "Cannot open video file"
            return result

        result["fps"]         = round(cap.get(cv2.CAP_PROP_FPS), 2)
        result["frame_count"] = int(cap.get(cv2.CAP_PROP_FRAME_COUNT))
        w = int(cap.get(cv2.CAP_PROP_FRAME_WIDTH))
        h = int(cap.get(cv2.CAP_PROP_FRAME_HEIGHT))
        result["resolution"]  = f"{w} × {h}"
        if result["fps"] > 0 and result["frame_count"] > 0:
            result["duration_sec"] = round(result["frame_count"] / result["fps"], 2)

        # Sample up to 5 evenly-spaced frames for stego analysis
        n_samples = min(5, max(1, result["frame_count"]))
        interval  = max(1, result["frame_count"] // n_samples)
        frame_results = []
        for i in range(n_samples):
            cap.set(cv2.CAP_PROP_POS_FRAMES, i * interval)
            ret, frame = cap.read()
            if ret:
                gray = cv2.cvtColor(frame, cv2.COLOR_BGR2GRAY)
                feats = extract_features(gray)
                is_stego, conf = classify_ml(feats)
                frame_results.append({
                    "frame": i * interval,
                    "is_stego": is_stego,
                    "confidence": round(conf, 1)
                })
        cap.release()

        result["frame_analysis"] = frame_results
        stego_frames = sum(1 for f in frame_results if f["is_stego"])
        if stego_frames > 0:
            result["suspicious"] = True
            result["suspicious_reasons"].append(
                f"{stego_frames}/{n_samples} sampled frames contain potential hidden data")

    except Exception as e:
        result["error"] = str(e)
    return result


# ══════════════════════════════════════════════════════════════
#  FILE RECONSTRUCTION ENGINE
# ══════════════════════════════════════════════════════════════

# Temp storage: repair_id → repaired file path (cleared after download)
_REPAIRED_FILES: dict = {}

# Known good magic bytes for each extension
FILE_MAGIC: dict = {
    'jpg':  [b'\xff\xd8\xff'],
    'jpeg': [b'\xff\xd8\xff'],
    'png':  [b'\x89PNG\r\n\x1a\n'],
    'gif':  [b'GIF87a', b'GIF89a'],
    'bmp':  [b'BM'],
    'webp': [b'RIFF'],
    'tiff': [b'II*\x00', b'MM\x00*'],
    'pdf':  [b'%PDF-'],
    'wav':  [b'RIFF'],
    'mp3':  [b'ID3', b'\xff\xfb', b'\xff\xf3', b'\xff\xf2', b'\xff\xfa'],
    'ogg':  [b'OggS'],
    'flac': [b'fLaC'],
    'mkv':  [b'\x1a\x45\xdf\xa3'],
    'flv':  [b'FLV\x01'],
    'avi':  [b'RIFF'],
    'docx': [b'PK\x03\x04'], 'xlsx': [b'PK\x03\x04'],
    'pptx': [b'PK\x03\x04'], 'odt':  [b'PK\x03\x04'],
    'odf':  [b'PK\x03\x04'], 'ods':  [b'PK\x03\x04'],
    'odp':  [b'PK\x03\x04'], 'apk':  [b'PK\x03\x04'],
    'zip':  [b'PK\x03\x04'],
}

# Human-readable descriptions
FILE_MAGIC_DESC: dict = {
    'jpg':  'FF D8 FF  (JPEG SOI)',
    'jpeg': 'FF D8 FF  (JPEG SOI)',
    'png':  '89 50 4E 47 0D 0A 1A 0A  (PNG signature)',
    'gif':  '47 49 46 38 37/39 61  (GIF87a / GIF89a)',
    'bmp':  '42 4D  (BM)',
    'pdf':  '25 50 44 46 2D  (%PDF-)',
    'wav':  '52 49 46 46 … 57 41 56 45  (RIFF…WAVE)',
    'mp3':  '49 44 33  (ID3) or FF FB/F3/F2/FA  (MPEG sync)',
    'ogg':  '4F 67 67 53  (OggS)',
    'flac': '66 4C 61 43  (fLaC)',
    'mkv':  '1A 45 DF A3  (EBML)',
    'avi':  '52 49 46 46 … 41 56 49 20  (RIFF…AVI )',
    'webp': '52 49 46 46 … 57 45 42 50  (RIFF…WEBP)',
    'docx': '50 4B 03 04  (PK ZIP)',
    'apk':  '50 4B 03 04  (PK ZIP)',
}


def _hex_preview(data: bytes, n: int = 32) -> str:
    """Return hex string of first n bytes, grouped in pairs."""
    chunk = data[:n]
    return ' '.join(f'{b:02X}' for b in chunk)


# ── JPEG ──────────────────────────────────────────────────────
def _repair_jpeg(data: bytes) -> dict:
    r = {"corruption_found": [], "repairs_applied": [], "repaired": False, "repaired_data": None}
    SOI = b'\xff\xd8\xff'
    EOI = b'\xff\xd9'
    working = bytearray(data)

    # Find SOI marker
    soi_pos = data.find(SOI)
    if soi_pos == -1:
        r["corruption_found"].append("JPEG SOI marker (FF D8 FF) is missing — not a valid JPEG")
        r["error"] = "Cannot locate JPEG data in file"
        return r
    if soi_pos > 0:
        r["corruption_found"].append(
            f"Leading garbage: {soi_pos} byte(s) before JPEG SOI marker")
        working = bytearray(data[soi_pos:])
        r["repairs_applied"].append(f"Trimmed {soi_pos} leading garbage byte(s)")
        r["repaired"] = True

    # Check / add EOI
    if not bytes(working).endswith(EOI):
        r["corruption_found"].append("JPEG EOI marker (FF D9) is missing — file may be truncated")
        working.extend(EOI)
        r["repairs_applied"].append("Appended JPEG EOI marker (FF D9)")
        r["repaired"] = True

    # Try PIL verify
    try:
        Image.open(io.BytesIO(bytes(working))).verify()
    except Exception as e:
        # Try re-encode via PIL as last resort
        try:
            img = Image.open(io.BytesIO(bytes(working)))
            buf = io.BytesIO()
            img.save(buf, format="JPEG", quality=95)
            working = bytearray(buf.getvalue())
            r["corruption_found"].append(f"JPEG structure error: {e}")
            r["repairs_applied"].append("Re-encoded image via PIL to fix internal structure")
            r["repaired"] = True
        except Exception as e2:
            r["corruption_found"].append(f"Could not verify JPEG structure: {e2}")

    if not r["corruption_found"]:
        r["corruption_found"] = ["No corruption detected — file signature is intact"]

    r["repaired_data"] = bytes(working) if r["repaired"] else None
    return r


# ── PNG ───────────────────────────────────────────────────────
def _repair_png(data: bytes) -> dict:
    r = {"corruption_found": [], "repairs_applied": [], "repaired": False, "repaired_data": None}
    PNG_SIG  = b'\x89PNG\r\n\x1a\n'
    PNG_IEND = b'\x00\x00\x00\x00IEND\xaeB`\x82'
    working  = bytearray(data)

    if not data.startswith(PNG_SIG):
        sig_pos = data.find(PNG_SIG)
        if sig_pos > 0:
            working = bytearray(data[sig_pos:])
            r["corruption_found"].append(
                f"PNG signature found at offset {sig_pos} — {sig_pos} leading garbage byte(s)")
            r["repairs_applied"].append(f"Trimmed {sig_pos} leading garbage byte(s)")
            r["repaired"] = True
        else:
            # Try to locate IHDR chunk and prepend signature
            ihdr = data.find(b'IHDR')
            if ihdr >= 4:
                working = bytearray(PNG_SIG) + bytearray(data[ihdr - 4:])
                r["corruption_found"].append("PNG signature missing; IHDR chunk found inside file")
                r["repairs_applied"].append("Prepended PNG 8-byte signature before IHDR chunk")
                r["repaired"] = True
            else:
                r["corruption_found"].append("PNG signature (89 50 4E 47) and IHDR chunk both missing")
                r["error"] = "Cannot locate PNG data"
                return r

    if not bytes(working).endswith(b'\xaeB`\x82'):
        working.extend(PNG_IEND)
        r["corruption_found"].append("PNG IEND chunk missing — file appears truncated")
        r["repairs_applied"].append("Appended IEND chunk to complete PNG structure")
        r["repaired"] = True

    # Try PIL verify; if fails, attempt re-encode
    try:
        Image.open(io.BytesIO(bytes(working))).load()
    except Exception as e:
        try:
            img = Image.open(io.BytesIO(data))
            buf = io.BytesIO()
            img.save(buf, format="PNG")
            working = bytearray(buf.getvalue())
            r["corruption_found"].append(f"PNG chunk structure error: {e}")
            r["repairs_applied"].append("Re-encoded via PIL to rebuild chunk structure")
            r["repaired"] = True
        except Exception as e2:
            r["corruption_found"].append(f"PNG structure issue: {e2}")

    if not r["corruption_found"]:
        r["corruption_found"] = ["No corruption detected — file signature is intact"]

    r["repaired_data"] = bytes(working) if r["repaired"] else None
    return r


# ── GIF ───────────────────────────────────────────────────────
def _repair_gif(data: bytes) -> dict:
    r = {"corruption_found": [], "repairs_applied": [], "repaired": False, "repaired_data": None}
    HEADERS = [b'GIF87a', b'GIF89a']
    working = bytearray(data)

    has_header = any(data.startswith(h) for h in HEADERS)
    if not has_header:
        for hdr in HEADERS:
            pos = data.find(hdr)
            if pos > 0:
                working = bytearray(data[pos:])
                r["corruption_found"].append(
                    f"GIF header found at offset {pos} — {pos} leading byte(s) stripped")
                r["repairs_applied"].append("Trimmed leading garbage before GIF header")
                r["repaired"] = True
                break
        else:
            r["corruption_found"].append("GIF signature (GIF87a/GIF89a) not found")
            working = bytearray(b'GIF89a') + bytearray(data)
            r["repairs_applied"].append("Prepended GIF89a header (width/height may be wrong)")
            r["repaired"] = True

    # Check GIF trailer byte 0x3B
    if not bytes(working).endswith(b'\x3b'):
        working.extend(b'\x3b')
        r["corruption_found"].append("GIF trailer byte (0x3B) missing — file truncated")
        r["repairs_applied"].append("Appended GIF trailer byte (3B)")
        r["repaired"] = True

    if not r["corruption_found"]:
        r["corruption_found"] = ["No corruption detected — file signature is intact"]

    r["repaired_data"] = bytes(working) if r["repaired"] else None
    return r


# ── BMP ───────────────────────────────────────────────────────
def _repair_bmp(data: bytes) -> dict:
    r = {"corruption_found": [], "repairs_applied": [], "repaired": False, "repaired_data": None}
    working = bytearray(data)

    if not data.startswith(b'BM'):
        bm_pos = data.find(b'BM')
        if bm_pos > 0:
            working = bytearray(data[bm_pos:])
            r["corruption_found"].append(
                f"BM signature found at offset {bm_pos} — leading garbage stripped")
            r["repairs_applied"].append("Trimmed leading garbage before BM signature")
            r["repaired"] = True
        else:
            r["corruption_found"].append("BMP signature 'BM' not found")
            r["error"] = "Cannot locate BMP data"
            return r

    # Fix file size field (bytes 2-5, little-endian)
    if len(working) >= 6:
        reported = struct.unpack_from('<I', working, 2)[0]
        actual   = len(working)
        if reported != actual:
            struct.pack_into('<I', working, 2, actual)
            r["corruption_found"].append(
                f"BMP file size field mismatch: header says {reported}, actual {actual}")
            r["repairs_applied"].append(f"Corrected BMP file size field to {actual}")
            r["repaired"] = True

    if not r["corruption_found"]:
        r["corruption_found"] = ["No corruption detected — file signature is intact"]

    r["repaired_data"] = bytes(working) if r["repaired"] else None
    return r


# ── WAV ───────────────────────────────────────────────────────
def _repair_wav(data: bytes) -> dict:
    r = {"corruption_found": [], "repairs_applied": [], "repaired": False, "repaired_data": None}
    working = bytearray(data)

    if not data.startswith(b'RIFF'):
        riff_pos = data.find(b'RIFF')
        if riff_pos > 0 and data[riff_pos + 8: riff_pos + 12] == b'WAVE':
            working = bytearray(data[riff_pos:])
            r["corruption_found"].append(
                f"RIFF/WAVE header found at offset {riff_pos} — leading garbage stripped")
            r["repairs_applied"].append("Trimmed leading garbage before RIFF header")
            r["repaired"] = True
        else:
            # Try to find 'fmt ' chunk and rebuild header
            fmt_pos = data.find(b'fmt ')
            if fmt_pos > 0:
                audio_rest = data[fmt_pos:]
                new_size   = len(audio_rest) + 4  # 4 for 'WAVE'
                header     = struct.pack('<4sI4s', b'RIFF', new_size, b'WAVE')
                working    = bytearray(header) + bytearray(audio_rest)
                r["corruption_found"].append("RIFF/WAVE header missing — fmt chunk found")
                r["repairs_applied"].append("Reconstructed RIFF/WAVE header from fmt chunk")
                r["repaired"] = True
            else:
                r["corruption_found"].append(
                    "RIFF header and fmt chunk both missing — cannot reconstruct WAV")
                r["error"] = "Critical WAV structure missing"
                return r
    else:
        # Check WAVE marker at offset 8
        if working[8:12] != b'WAVE':
            working[8:12] = b'WAVE'
            r["corruption_found"].append("WAVE marker at offset 8 is corrupted")
            r["repairs_applied"].append("Restored WAVE marker at offset 8")
            r["repaired"] = True

        # Fix RIFF chunk size (offset 4, should be file_size - 8)
        if len(working) >= 8:
            expected_size = len(working) - 8
            reported_size = struct.unpack_from('<I', working, 4)[0]
            if abs(expected_size - reported_size) > 8:
                struct.pack_into('<I', working, 4, expected_size)
                r["corruption_found"].append(
                    f"RIFF chunk size mismatch: reported {reported_size}, expected {expected_size}")
                r["repairs_applied"].append(f"Fixed RIFF chunk size to {expected_size}")
                r["repaired"] = True

    if not r["corruption_found"]:
        r["corruption_found"] = ["No corruption detected — file signature is intact"]

    r["repaired_data"] = bytes(working) if r["repaired"] else None
    return r


# ── MP3 ───────────────────────────────────────────────────────
def _repair_mp3(data: bytes) -> dict:
    r = {"corruption_found": [], "repairs_applied": [], "repaired": False, "repaired_data": None}
    ID3_HDR    = b'ID3'
    SYNC_WORDS = [b'\xff\xfb', b'\xff\xf3', b'\xff\xf2', b'\xff\xfa', b'\xff\xf0']
    working    = bytearray(data)

    # Find first valid sync word or ID3 tag
    best_pos = len(data)
    if data.startswith(ID3_HDR):
        best_pos = 0
    else:
        id3_pos = data.find(ID3_HDR)
        if id3_pos > 0:
            best_pos = id3_pos
        for sw in SYNC_WORDS:
            pos = data.find(sw)
            if 0 <= pos < best_pos:
                best_pos = pos

    if best_pos == len(data):
        r["corruption_found"].append(
            "No MP3 frame sync (FF FB/FA/F3/F2) or ID3 header found — may not be MP3")
        r["error"] = "Cannot locate MP3 audio data"
        return r

    if best_pos > 0:
        working = bytearray(data[best_pos:])
        r["corruption_found"].append(
            f"MP3 data starts at offset {best_pos} — {best_pos} byte(s) of leading garbage")
        r["repairs_applied"].append(f"Trimmed {best_pos} leading garbage byte(s)")
        r["repaired"] = True

    if not r["corruption_found"]:
        r["corruption_found"] = ["No corruption detected — file signature is intact"]

    r["repaired_data"] = bytes(working) if r["repaired"] else None
    return r


# ── PDF ───────────────────────────────────────────────────────
def _repair_pdf(data: bytes) -> dict:
    r = {"corruption_found": [], "repairs_applied": [], "repaired": False, "repaired_data": None}
    PDF_HDR = b'%PDF-'
    PDF_EOF = b'%%EOF'
    working = bytearray(data)

    if not data.startswith(PDF_HDR):
        hdr_pos = data.find(PDF_HDR)
        if hdr_pos > 0:
            working = bytearray(data[hdr_pos:])
            r["corruption_found"].append(
                f"PDF header found at offset {hdr_pos} — {hdr_pos} leading byte(s) stripped")
            r["repairs_applied"].append("Trimmed leading garbage before %PDF- header")
            r["repaired"] = True
        else:
            working = bytearray(b'%PDF-1.4\n') + bytearray(data)
            r["corruption_found"].append("%PDF- header completely missing")
            r["repairs_applied"].append("Prepended default %PDF-1.4 header")
            r["repaired"] = True

    if PDF_EOF not in bytes(working)[-256:]:
        working.extend(b'\n%%EOF\n')
        r["corruption_found"].append("%%EOF marker missing — PDF appears truncated")
        r["repairs_applied"].append("Appended %%EOF marker")
        r["repaired"] = True

    if not r["corruption_found"]:
        r["corruption_found"] = ["No corruption detected — file signature is intact"]

    r["repaired_data"] = bytes(working) if r["repaired"] else None
    return r


# ── ZIP-BASED (DOCX / ODF / APK) ────────────────────────────
def _rebuild_zip_central_dir(data: bytes) -> bytes | None:
    """Scan for PK local-file-headers and rebuild the central directory."""
    entries = []
    pos     = 0
    while pos < len(data) - 30:
        if data[pos: pos + 4] != b'PK\x03\x04':
            pos += 1
            continue
        try:
            (ver_need, flags, compress, mod_time, mod_date,
             crc32_val, comp_size, uncomp_size,
             fname_len, extra_len) = struct.unpack_from('<HHHHHIIIHH', data, pos + 4)
            if fname_len > 4096 or extra_len > 65536 or comp_size > len(data):
                pos += 1
                continue
            fname_start = pos + 30
            if fname_start + fname_len > len(data):
                pos += 1
                continue
            fname      = data[fname_start: fname_start + fname_len]
            data_start = fname_start + fname_len + extra_len
            entries.append({
                'offset': pos, 'fname': fname,
                'ver_need': ver_need, 'flags': flags,
                'compress': compress, 'mod_time': mod_time, 'mod_date': mod_date,
                'crc32': crc32_val, 'comp_size': comp_size, 'uncomp_size': uncomp_size,
            })
            pos = data_start + max(0, comp_size)
        except Exception:
            pos += 1

    if not entries:
        return None

    last_end = max(
        e['offset'] + 30 + len(e['fname']) + max(0, e['comp_size'])
        for e in entries
    )
    out      = bytearray(data[: min(last_end, len(data))])
    cd_start = len(out)
    cd_buf   = bytearray()

    for e in entries:
        fn = e['fname']
        cd_buf.extend(struct.pack(
            '<IHHHHHIIIHHHHHII',
            0x02014b50,
            20, e['ver_need'], e['flags'], e['compress'], e['mod_time'], e['mod_date'],
            e['crc32'], e['comp_size'], e['uncomp_size'],
            len(fn), 0, 0, 0, 0, 0, e['offset'],
        ))
        cd_buf.extend(fn)

    out.extend(cd_buf)
    out.extend(struct.pack(
        '<IHHHHIIH',
        0x06054b50, 0, 0, len(entries), len(entries), len(cd_buf), cd_start, 0,
    ))
    return bytes(out)


def _repair_zip_based(data: bytes, ext: str) -> dict:
    r = {"corruption_found": [], "repairs_applied": [], "repaired": False, "repaired_data": None}
    ZIP_SIG = b'PK\x03\x04'

    if not data.startswith(ZIP_SIG):
        pos = data.find(ZIP_SIG)
        if pos > 0:
            data = data[pos:]
            r["corruption_found"].append(
                f"ZIP signature found at offset {pos} — leading garbage stripped")
            r["repairs_applied"].append("Trimmed leading garbage before PK\\x03\\x04")
            r["repaired"] = True
        else:
            r["corruption_found"].append("ZIP/PK signature not found — file is not a valid archive")
            r["error"] = "Not a valid ZIP-based file"
            return r

    try:
        with zipfile.ZipFile(io.BytesIO(data), 'r') as z:
            file_list = z.namelist()
            r["corruption_found"].append(
                f"ZIP structure valid — {len(file_list)} entries readable")
    except zipfile.BadZipFile as e:
        r["corruption_found"].append(f"ZIP central directory corrupted: {e}")
        rebuilt = _rebuild_zip_central_dir(data)
        if rebuilt:
            # Verify rebuilt archive
            try:
                with zipfile.ZipFile(io.BytesIO(rebuilt), 'r') as zv:
                    recovered = len(zv.namelist())
                r["repairs_applied"].append(
                    f"Rebuilt ZIP central directory — {recovered} file(s) recovered")
                r["repaired"] = True
                data = rebuilt
            except Exception as ve:
                r["corruption_found"].append(f"Rebuilt archive still unreadable: {ve}")
        else:
            r["corruption_found"].append("Could not find any local file headers to rebuild from")
            r["error"] = "ZIP archive is too badly corrupted to repair"

    if not r["corruption_found"] or all("valid" in c for c in r["corruption_found"]):
        r["corruption_found"] = r["corruption_found"] or ["No corruption detected"]

    r["repaired_data"] = bytes(data) if r["repaired"] else None
    return r


# ── VIDEO / MKV / AVI (detection only) ──────────────────────
def _detect_video(data: bytes, ext: str) -> dict:
    r = {"corruption_found": [], "repairs_applied": [], "repaired": False, "repaired_data": None}
    sigs = {
        'mp4':  (None, "MP4: look for 'ftyp' at offset 4"),
        'mov':  (None, "MOV: QuickTime container, 'ftyp'/'moov' boxes"),
        'avi':  (b'RIFF', "AVI: RIFF…AVI  container"),
        'mkv':  (b'\x1a\x45\xdf\xa3', "MKV: EBML 1A 45 DF A3"),
        'flv':  (b'FLV\x01', "FLV: 46 4C 56 01"),
        'webm': (b'\x1a\x45\xdf\xa3', "WebM: EBML 1A 45 DF A3"),
    }
    sig, desc = sigs.get(ext, (None, ext.upper()))

    if sig and not data.startswith(sig):
        pos = data.find(sig)
        if pos > 0:
            r["corruption_found"].append(
                f"Valid {ext.upper()} signature found at offset {pos} — {pos} garbage byte(s)")
            r["repairs_applied"].append(
                f"Automatic trim possible. However full {ext.upper()} container repair "
                f"requires ffmpeg: `ffmpeg -i corrupt.{ext} -c copy repaired.{ext}`")
        else:
            r["corruption_found"].append(
                f"{ext.upper()} signature not found. Expected {desc}")
    elif ext in ('mp4', 'mov'):
        ftyp = data.find(b'ftyp')
        if ftyp == -1:
            r["corruption_found"].append(
                "MP4/MOV 'ftyp' atom not found — container may be severely truncated")
            r["repairs_applied"].append(
                "Use ffmpeg to attempt repair: `ffmpeg -i corrupt.mp4 -c copy repaired.mp4`")
        else:
            moov = data.find(b'moov')
            if moov == -1:
                r["corruption_found"].append(
                    "'moov' atom missing — video is unplayable (incomplete download?)")
                r["repairs_applied"].append(
                    "Run `ffmpeg -i corrupt.mp4 -movflags faststart repaired.mp4` to rebuild moov")
            else:
                r["corruption_found"].append("MP4 ftyp and moov atoms found — structure looks intact")

    if not r["corruption_found"]:
        r["corruption_found"] = ["No signature corruption detected"]

    r["note"] = (f"{ext.upper()} repair requires ffmpeg or specialized tools. "
                 "This tool performs signature detection only for video containers.")
    return r


# ── Main repair dispatcher ────────────────────────────────────
def repair_file(fpath: str, ext: str, original_name: str) -> dict:
    result = {
        "file_type":       ext.upper(),
        "original_name":   original_name,
        "original_size":   0,
        "repaired_size":   0,
        "hex_before":      "",
        "hex_after":       "",
        "expected_magic":  FILE_MAGIC_DESC.get(ext, "N/A"),
        "actual_magic":    "",
        "signature_match": False,
        "corruption_found":  [],
        "repairs_applied":   [],
        "repair_success":    False,
        "can_open":          False,
        "repaired_b64":      None,
        "repair_download_url": None,
        "note":              "",
        "error":             None,
    }

    try:
        with open(fpath, 'rb') as f:
            data = f.read()

        result["original_size"] = len(data)
        result["hex_before"]    = _hex_preview(data, 32)
        result["actual_magic"]  = _hex_preview(data, 8)

        # Check signature match
        known_sigs = FILE_MAGIC.get(ext, [])
        result["signature_match"] = any(data.startswith(s) for s in known_sigs)

        ext = ext.lower()
        if ext in ('jpg', 'jpeg'):
            rep = _repair_jpeg(data)
        elif ext == 'png':
            rep = _repair_png(data)
        elif ext == 'gif':
            rep = _repair_gif(data)
        elif ext == 'bmp':
            rep = _repair_bmp(data)
        elif ext == 'wav':
            rep = _repair_wav(data)
        elif ext == 'mp3':
            rep = _repair_mp3(data)
        elif ext == 'pdf':
            rep = _repair_pdf(data)
        elif ext in ('docx', 'xlsx', 'pptx', 'odt', 'odf', 'ods', 'odp', 'apk', 'zip'):
            rep = _repair_zip_based(data, ext)
        elif ext in ('mp4', 'mov', 'avi', 'mkv', 'flv', 'webm', 'wmv', '3gp'):
            rep = _detect_video(data, ext)
        else:
            # Generic: just report signature
            if result["signature_match"]:
                rep = {"corruption_found": ["Signature matches — no obvious header corruption"],
                       "repairs_applied": [], "repaired": False, "repaired_data": None}
            else:
                rep = {"corruption_found": [f"Signature mismatch for .{ext} file"],
                       "repairs_applied": ["No automatic repair available for this format"],
                       "repaired": False, "repaired_data": None}

        result["corruption_found"] = rep.get("corruption_found", [])
        result["repairs_applied"]  = rep.get("repairs_applied", [])
        result["repair_success"]   = rep.get("repaired", False)
        result["note"]             = rep.get("note", "")
        if rep.get("error"):
            result["error"] = rep["error"]

        repaired_data = rep.get("repaired_data")
        if repaired_data:
            result["repaired_size"] = len(repaired_data)
            result["hex_after"]     = _hex_preview(repaired_data, 32)

            # Small files (≤ 15 MB): return base64 inline
            if len(repaired_data) <= 15 * 1024 * 1024:
                result["repaired_b64"] = base64.b64encode(repaired_data).decode()
            else:
                rid   = uuid.uuid4().hex
                rpath = os.path.join(UPLOAD_DIR, f"repair_{rid}.{ext}")
                with open(rpath, 'wb') as f:
                    f.write(repaired_data)
                _REPAIRED_FILES[rid] = rpath
                result["repair_download_url"] = f"/download-repaired/{rid}"

            # Verify repaired file can actually be opened
            try:
                if ext in ('jpg', 'jpeg', 'png', 'gif', 'bmp', 'webp', 'tiff'):
                    Image.open(io.BytesIO(repaired_data)).verify()
                    result["can_open"] = True
                elif ext in ('docx', 'xlsx', 'pptx', 'odt', 'odf', 'ods', 'odp', 'apk', 'zip'):
                    with zipfile.ZipFile(io.BytesIO(repaired_data), 'r') as z:
                        z.namelist()
                    result["can_open"] = True
                elif ext == 'pdf':
                    result["can_open"] = repaired_data[:5] == b'%PDF-'
                elif ext == 'wav':
                    import wave
                    wave.open(io.BytesIO(repaired_data), 'rb').close()
                    result["can_open"] = True
                else:
                    result["can_open"] = True
            except Exception:
                result["can_open"] = False
        else:
            result["hex_after"] = result["hex_before"]
            result["can_open"]  = result["signature_match"]

    except Exception as e:
        result["error"] = str(e)

    return result


# ══════════════════════════════════════════════════════════════
#  FLASK ROUTES
# ══════════════════════════════════════════════════════════════
@app.route("/")
def index():
    return render_template("index.html")

@app.route("/about")
def about():
    return render_template("about.html")

@app.route("/apk")
def apk_dashboard():
    return render_template("apk.html")

@app.route("/repair")
def repair_dashboard():
    return render_template("repair.html")

@app.route("/health")
def health():
    return jsonify({
        "status": "ok",
        "model":  "RandomForest (numpy+opencv)" if MODEL_LOADED else "rule-based",
        "supported_types": sorted(ALLOWED),
    })


@app.route("/analyse", methods=["POST"])
def analyse():
    field = "image" if "image" in request.files else "file"
    if field not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files[field]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED:
        return jsonify({"error": f"Unsupported format '{ext}'. Accepted: images, PDF, DOCX, ODT, MP3, WAV, MP4, APK and more."}), 400

    t0    = time.perf_counter()
    fname = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
    fpath = os.path.join(UPLOAD_DIR, fname)
    file.save(fpath)

    try:
        # ── Route by file category ───────────────────────────
        if ext in PDF_TYPES:
            analysis  = analyze_pdf(fpath)
            proc_ms   = round((time.perf_counter() - t0) * 1000, 1)
            return jsonify({"file_type": "pdf", "filename": file.filename,
                            "proc_time_ms": proc_ms, "analysis": analysis})

        if ext in OFFICE_TYPES:
            analysis  = analyze_office(fpath, ext)
            proc_ms   = round((time.perf_counter() - t0) * 1000, 1)
            return jsonify({"file_type": "office", "filename": file.filename,
                            "proc_time_ms": proc_ms, "analysis": analysis})

        if ext in AUDIO_TYPES:
            analysis  = analyze_audio(fpath, ext)
            proc_ms   = round((time.perf_counter() - t0) * 1000, 1)
            return jsonify({"file_type": "audio", "filename": file.filename,
                            "proc_time_ms": proc_ms, "analysis": analysis})

        if ext in VIDEO_TYPES:
            analysis  = analyze_video(fpath, ext)
            proc_ms   = round((time.perf_counter() - t0) * 1000, 1)
            return jsonify({"file_type": "video", "filename": file.filename,
                            "proc_time_ms": proc_ms, "analysis": analysis})

        if ext in APK_TYPES:
            analysis  = analyze_apk(fpath)
            proc_ms   = round((time.perf_counter() - t0) * 1000, 1)
            return jsonify({"file_type": "apk", "filename": file.filename,
                            "proc_time_ms": proc_ms, "analysis": analysis})

        # ── Image analysis (default) ─────────────────────────
        img_pil = Image.open(fpath)
        w, h    = img_pil.size

        img_cv = cv2.imread(fpath, cv2.IMREAD_GRAYSCALE)
        if img_cv is None:
            img_cv = np.array(img_pil.convert("L"), dtype=np.uint8)

        hidden_text          = get_hidden_text(img_pil)
        feats                = extract_features(img_cv)
        is_stego, confidence = classify_ml(feats, hidden_text)
        residual_b64         = make_residual_b64(img_cv)

        orig = img_pil.convert("RGB")
        orig.thumbnail((480, 480))
        buf = io.BytesIO(); orig.save(buf, format="PNG")
        orig_b64 = base64.b64encode(buf.getvalue()).decode()

        proc_ms = round((time.perf_counter() - t0) * 1000, 1)

        names = [
            "Mean (r3)", "Std Dev (r3)", "Variance (r3)", "Energy (r3)", "Skewness (r3)", "Kurtosis (r3)",
            "Mean (r5)", "Std Dev (r5)", "Variance (r5)", "Energy (r5)", "Skewness (r5)", "Kurtosis (r5)",
            "LSB Mean", "LSB Variance", "Even Pixel Ratio", "LSB Autocorr.",
        ]
        feats_d = [{"name": n, "value": round(float(v), 6)} for n, v in zip(names, feats)]
        conf_n  = round(100 - confidence, 2) if is_stego else round(confidence, 2)
        conf_s  = round(confidence, 2)       if is_stego else round(100 - confidence, 2)

        return jsonify({
            "file_type":         "image",
            "label":             "Steganographic" if is_stego else "Normal",
            "is_stego":          is_stego,
            "confidence":        round(confidence, 2),
            "confidence_normal": conf_n,
            "confidence_stego":  conf_s,
            "features":          feats_d,
            "image_b64":         orig_b64,
            "residual_b64":      residual_b64,
            "dimensions":        f"{w} × {h} px",
            "proc_time_ms":      proc_ms,
            "filename":          file.filename,
            "hidden_text":       hidden_text or "",
            "text_found":        bool(hidden_text and len(hidden_text) >= 2),
            "text_length":       len(hidden_text) if hidden_text else 0,
            "engine":            "NumPy + OpenCV + RandomForest" if MODEL_LOADED else "Rule-based",
        })

    except Exception as ex:
        return jsonify({"error": f"Analysis failed: {str(ex)}"}), 500
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


@app.route("/analyse-apk", methods=["POST"])
def analyse_apk_route():
    if "apk" not in request.files:
        return jsonify({"error": "No APK file uploaded (field name: 'apk')"}), 400
    file = request.files["apk"]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400
    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext != "apk":
        return jsonify({"error": "Only .apk files are accepted on this endpoint"}), 400

    t0    = time.perf_counter()
    fname = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
    fpath = os.path.join(UPLOAD_DIR, fname)
    file.save(fpath)

    try:
        analysis = analyze_apk(fpath)
        proc_ms  = round((time.perf_counter() - t0) * 1000, 1)
        return jsonify({
            "filename":     file.filename,
            "proc_time_ms": proc_ms,
            **analysis,
        })
    except Exception as ex:
        return jsonify({"error": f"APK analysis failed: {str(ex)}"}), 500
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


@app.route("/repair-file", methods=["POST"])
def repair_file_route():
    field = next((k for k in ("file", "image", "apk") if k in request.files), None)
    if not field:
        return jsonify({"error": "No file uploaded"}), 400
    file = request.files[field]
    if not file.filename:
        return jsonify({"error": "No file selected"}), 400

    ext = file.filename.rsplit(".", 1)[-1].lower() if "." in file.filename else ""
    if ext not in ALLOWED:
        return jsonify({"error": f"Unsupported format '.{ext}' — use an image, audio, video, PDF, Office, or APK file"}), 400

    t0    = time.perf_counter()
    fname = f"{uuid.uuid4().hex}_{secure_filename(file.filename)}"
    fpath = os.path.join(UPLOAD_DIR, fname)
    file.save(fpath)

    try:
        result              = repair_file(fpath, ext, file.filename)
        result["proc_time_ms"] = round((time.perf_counter() - t0) * 1000, 1)
        return jsonify(result)
    except Exception as ex:
        return jsonify({"error": f"Repair failed: {str(ex)}"}), 500
    finally:
        if os.path.exists(fpath):
            os.remove(fpath)


@app.route("/download-repaired/<fid>")
def download_repaired(fid):
    fpath = _REPAIRED_FILES.pop(fid, None)
    if not fpath or not os.path.exists(fpath):
        return jsonify({"error": "Repaired file not found or already downloaded"}), 404
    ext  = fpath.rsplit(".", 1)[-1]
    name = f"repaired_{fid[:8]}.{ext}"
    try:
        return send_file(fpath, as_attachment=True, download_name=name)
    finally:
        try:
            os.remove(fpath)
        except Exception:
            pass


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  StegoDetect v2.0  —  Parul University CSE Dept")
    print("  Engine: NumPy + OpenCV + Random Forest ML")
    print(f"  Supported types: {', '.join(sorted(ALLOWED))}")
    print("  Open  : http://127.0.0.1:5000")
    print("  APK   : http://127.0.0.1:5000/apk")
    print("=" * 60 + "\n")
    app.run(debug=True, host="0.0.0.0", port=5000)

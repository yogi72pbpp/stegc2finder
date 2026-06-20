# 🔍 StegoDetect v2.0 — Steganography Detection System
### Detection of Steganography and Malicious File Analysis
**Parul Institute of Technology · CSE Dept · Minor Project II · AY 2026-27**
**Engine: NumPy + OpenCV + Random Forest ML**

---

## 👥 Team
| Name | Enrollment No. |
|---|---|
| Jignesh Kumar | 23030512600 |
| Praveen Yogi | 23030512601 |
| Aluel Mayuol Madut Yel | 2303051260053 |
| Lilian John Mwakamala | 2303051260026 |

**Guide:** Ms. Sweety Mahendrabhai Patel (Asst. Professor, CSE Dept.)

---

## 🚀 How to Run (Step by Step)

### STEP 1 — Install Python 3.10+
Download from https://www.python.org/downloads/
> Tick **"Add Python to PATH"** during installation

### STEP 2 — Open terminal in this folder
```
cd path\to\StegoDetect_v2
```

### STEP 3 — Install libraries
```
py -m pip install -r requirements.txt
```

### STEP 4 — (Optional) Retrain the model
The trained model `model/stego_model.pkl` is already included.
To retrain from scratch:
```
py model/train_model.py
```

### STEP 5 — Run the app
```
py app.py
```

### STEP 6 — Open browser
```
http://127.0.0.1:5000
```

---

## 🎯 Demo for Mentor

### Normal image test:
- Upload any regular photo (selfie, landscape, etc.)
- Result: ✅ Normal Image (green banner)

### Steganographic image test:
1. Go to **https://stylesuxx.github.io/steganography/**
2. Upload any image → type a secret message → click **Encode**
3. Download the encoded image
4. Upload it to StegoDetect
5. Result: ⚠️ Steganographic Image + **the hidden text is shown!**

---

## ⚙️ How It Works

```
Image Upload (PNG/JPG/BMP/GIF/TIFF, max 50MB)
        ↓
OpenCV — Convert to Grayscale
        ↓
NumPy + OpenCV — Multi-scale Gaussian Blur (3×3 and 5×5)
        ↓
NumPy — Compute Noise Residuals (Original - Blurred)
        ↓
NumPy — Extract 16 Statistical Features:
  Per scale: Mean, Std Dev, Variance, Energy, Skewness, Kurtosis
  LSB plane: Mean, Variance, Even Ratio, Autocorrelation
        ↓
Scikit-learn — Random Forest Classifier (300 trees, 100% accuracy)
        ↓
Pillow — LSB Text Extraction (3 methods)
        ↓
Flask — Return Result + Confidence + Hidden Text
```

---

## 📁 Files
| File | Purpose |
|---|---|
| `app.py` | Main Flask app — routes, features, LSB extraction |
| `model/train_model.py` | Train ML model (NumPy + OpenCV + Scikit-learn) |
| `model/stego_model.pkl` | Pre-trained Random Forest model |
| `templates/index.html` | Main detection page |
| `templates/about.html` | About/info page |
| `static/css/style.css` | Dark cybersecurity theme |
| `static/js/app.js` | Frontend drag-drop & result rendering |
| `requirements.txt` | All Python dependencies |

---

## 🛠️ Tech Stack
- **Python 3.x** — Core language
- **Flask** — Web framework
- **NumPy** — Statistical feature computation
- **OpenCV** — Image processing, Gaussian blur
- **Scikit-learn** — Random Forest classifier
- **Joblib** — Model save/load
- **Pillow** — Image handling, LSB extraction

---

## ❓ Troubleshooting
| Problem | Fix |
|---|---|
| `ModuleNotFoundError` | `py -m pip install -r requirements.txt` |
| Port 5000 in use | Change to `app.run(port=5001)` in app.py |
| DLL blocked (college laptop) | Use Google Colab instead |
| Model missing | `py model/train_model.py` |

---
*StegoDetect v2.0 · Parul Institute of Technology · Vadodara, Gujarat · AY 2026-27*

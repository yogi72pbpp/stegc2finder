"""
train_model.py — Train the steganography detection classifier
Uses NumPy + OpenCV + Scikit-learn
Run once: python model/train_model.py
"""
import numpy as np
import cv2
import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
from sklearn.preprocessing import StandardScaler
from sklearn.metrics import accuracy_score, classification_report
import os

def embed_lsb(img, ratio=0.4):
    flat = img.flatten().copy()
    n    = int(len(flat) * ratio)
    pattern = np.tile([0,1], n//2+1)[:n].astype(np.uint8)
    flat[:n] = (flat[:n] & 0xFE) | pattern
    return flat.reshape(img.shape)

def extract_features(img_gray):
    """12 noise-residual + LSB features using NumPy & OpenCV"""
    img_f   = img_gray.astype(np.float64)
    # ── Gaussian blur residuals at 3 scales ──────────────────
    b3      = cv2.GaussianBlur(img_gray.astype(np.float32),(3,3),0).astype(np.float64)
    b5      = cv2.GaussianBlur(img_gray.astype(np.float32),(5,5),0).astype(np.float64)
    r3      = (img_f - b3).flatten()
    r5      = (img_f - b5).flatten()

    def stats(r):
        m  = np.mean(r);  s = np.std(r) + 1e-8
        return [m, s, np.var(r), np.mean(r**2),
                float(np.mean(((r-m)/s)**3)),
                float(np.mean(((r-m)/s)**4))]

    # ── LSB plane features ────────────────────────────────────
    flat     = img_gray.flatten().astype(np.uint8)
    lsb      = flat & 1
    lsb_mean = float(np.mean(lsb))
    lsb_var  = float(np.var(lsb))
    even     = float(np.sum(flat % 2 == 0) / len(flat))
    lsb_ac   = float(np.corrcoef(lsb[:-1], lsb[1:])[0,1]) if len(lsb)>1 else 0.0

    return stats(r3) + stats(r5) + [lsb_mean, lsb_var, even, lsb_ac]

def generate_dataset(n=4000, seed=42):
    np.random.seed(seed)
    X, y = [], []
    for i in range(n):
        h = w = np.random.choice([64,128,256])
        xx, yy = np.meshgrid(np.linspace(0,255,w), np.linspace(0,255,h))
        fr = np.random.uniform(1,8); ph = np.random.uniform(0,6.28)
        base = np.sin(xx/w*fr*np.pi+ph)*60 + np.cos(yy/h*fr*np.pi)*40 + 128
        img  = np.clip(base + np.random.normal(0,15,(h,w)),0,255).astype(np.uint8)

        X.append(extract_features(img)); y.append(0)

        ratio = np.random.uniform(0.2, 0.5)
        stego = embed_lsb(img, ratio)
        X.append(extract_features(stego)); y.append(1)

        if (i+1) % 1000 == 0:
            print(f"  {(i+1)*2}/{n*2} samples done...")

    return np.array(X, dtype=np.float32), np.array(y)

if __name__ == "__main__":
    print("Generating training dataset...")
    X, y = generate_dataset(4000)
    Xtr, Xte, ytr, yte = train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)
    sc = StandardScaler()
    Xtr = sc.fit_transform(Xtr); Xte = sc.transform(Xte)

    print("Training Random Forest classifier (300 trees)...")
    clf = RandomForestClassifier(300, max_depth=15, random_state=42, n_jobs=-1)
    clf.fit(Xtr, ytr)

    acc = accuracy_score(yte, clf.predict(Xte))
    print(f"\nAccuracy: {acc*100:.1f}%")
    print(classification_report(yte, clf.predict(Xte), target_names=["Normal","Stego"]))

    out = os.path.join(os.path.dirname(__file__), "stego_model.pkl")
    joblib.dump({"model": clf, "scaler": sc, "n_features": X.shape[1]}, out)
    print(f"Model saved → {out}")

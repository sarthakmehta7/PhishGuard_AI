"""
PhishGuard AI — Real ML training pipeline.
Metrics are calculated from the downloaded real-source dataset; nothing is hard-coded.
"""
from pathlib import Path
import json, pickle
import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier, GradientBoostingClassifier, VotingClassifier
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import train_test_split, StratifiedKFold, cross_val_score
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import RobustScaler
from sklearn.metrics import accuracy_score, precision_score, recall_score, f1_score, confusion_matrix, classification_report
from utils.analyzer import extract_30_features, FEATURE_COLS

BASE = Path(__file__).resolve().parent
DATA = BASE/"dataset"/"phishing_dataset.csv"
MODEL_DIR = BASE/"models"
LABELS = {0:"Safe",1:"Suspicious / Malicious",2:"Phishing"}

def main():
    if not DATA.exists():
        raise SystemExit("Real dataset missing. Run: python dataset/download_real_dataset.py")

    raw = pd.read_csv(DATA)
    if not {"url","label"}.issubset(raw.columns):
        raise SystemExit("Dataset must contain url,label columns.")

    rows = []
    for i, r in raw.iterrows():
        try:
            f = extract_30_features(str(r["url"]))
            f["label"] = int(r["label"])
            rows.append(f)
        except Exception:
            continue
    df = pd.DataFrame(rows).dropna()
    if len(df) < 100:
        raise SystemExit("Too few usable real samples.")

    X = df[FEATURE_COLS].values
    y = df["label"].values
    classes = sorted(set(map(int,y)))
    if len(classes) < 2:
        raise SystemExit("Need at least two real classes to train.")

    Xtr, Xte, ytr, yte = train_test_split(
        X, y, test_size=0.20, random_state=42, stratify=y
    )

    rf = RandomForestClassifier(
        n_estimators=350, max_depth=None, min_samples_leaf=2,
        class_weight="balanced_subsample", random_state=42, n_jobs=-1
    )
    gb = GradientBoostingClassifier(n_estimators=250, learning_rate=0.05,
                                    max_depth=3, random_state=42)
    lr = LogisticRegression(max_iter=2000, class_weight="balanced")
    model = Pipeline([
        ("scaler", RobustScaler()),
        ("model", VotingClassifier(
            estimators=[("rf",rf),("gb",gb),("lr",lr)],
            voting="soft", weights=[3,2,1]
        ))
    ])

    print(f"Training on {len(Xtr)} samples; testing on {len(Xte)} held-out samples...")
    model.fit(Xtr,ytr)
    pred = model.predict(Xte)

    acc = accuracy_score(yte,pred)
    prec = precision_score(yte,pred,average="weighted",zero_division=0)
    rec = recall_score(yte,pred,average="weighted",zero_division=0)
    f1 = f1_score(yte,pred,average="weighted",zero_division=0)
    cm = confusion_matrix(yte,pred,labels=classes)

    print("\nACTUAL HELD-OUT TEST RESULTS")
    print(f"Accuracy : {acc:.4f}")
    print(f"Precision: {prec:.4f}")
    print(f"Recall   : {rec:.4f}")
    print(f"F1 Score : {f1:.4f}")
    print("\nConfusion matrix:\n",cm)
    print("\n", classification_report(yte,pred,labels=classes,
          target_names=[LABELS.get(c,str(c)) for c in classes],zero_division=0))

    min_class = min(np.bincount(y.astype(int)))
    folds = min(5, int(min_class))
    cv_mean = cv_std = None
    if folds >= 2:
        cv = StratifiedKFold(n_splits=folds,shuffle=True,random_state=42)
        scores = cross_val_score(model,X,y,cv=cv,scoring="f1_weighted",n_jobs=-1)
        cv_mean, cv_std = float(scores.mean()), float(scores.std())
        print(f"{folds}-fold CV weighted F1: {cv_mean:.4f} ± {cv_std:.4f}")

    # RF feature importance from fitted voting estimator
    vote = model.named_steps["model"]
    fitted_rf = vote.named_estimators_["rf"]
    importance = {f: round(float(v),6) for f,v in zip(FEATURE_COLS,fitted_rf.feature_importances_)}

    MODEL_DIR.mkdir(exist_ok=True)
    with open(MODEL_DIR/"phishguard_model.pkl","wb") as f: pickle.dump(model,f)
    metadata = {
        "dataset_samples": int(len(df)),
        "dataset_source": "OpenPhish + URLhaus + Tranco public feeds",
        "accuracy": float(acc), "precision": float(prec), "recall": float(rec), "f1_score": float(f1),
        "cv_mean": cv_mean, "cv_std": cv_std,
        "train_samples": int(len(Xtr)), "test_samples": int(len(Xte)),
        "features": FEATURE_COLS, "feature_importance": importance,
        "confusion_matrix": cm.tolist(), "classes": {str(k):v for k,v in LABELS.items()},
        "note": "Metrics are generated from the actual downloaded dataset at training time."
    }
    (MODEL_DIR/"model_metadata.json").write_text(json.dumps(metadata,indent=2),encoding="utf-8")
    print("\nModel and real metrics saved in models/")

if __name__=="__main__":
    main()

# PhishGuard AI — REAL ML Edition

**Made by Sarthak Mehta · Prajwal Kumar · Divyansh Yadav**

## What is real in this project?

- Real public training data downloaded from **OpenPhish**, **URLhaus**, and **Tranco**
- Real 30-feature URL feature extraction
- Actual held-out test Accuracy, Precision, Recall and F1 generated during training
- Random Forest + Gradient Boosting + Logistic Regression soft-voting ensemble
- Live DNS resolution
- Live SSL certificate inspection
- Live HTTP response and security-header checks
- Live WHOIS lookup when the WHOIS service responds
- SQLite scan history, dashboard, bulk scanning, blacklist and feedback

## Important honesty note

This project does **not** claim a fixed 100% accuracy and does not generate fake phishing URLs as its training data. The exact dataset size and metrics depend on the public feeds available when you run the downloader.

## Easiest way to run on Windows

1. Extract this ZIP.
2. Open the `phishguard` folder.
3. Double-click **RUN_PHISHGUARD.bat**.
4. The first run installs dependencies, downloads real public feeds, trains the model, and calculates actual metrics.
5. The browser opens at `http://127.0.0.1:5000`.

Internet is required on the first run and for live DNS/SSL/HTTP/WHOIS checks.

## Manual VS Code workflow

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python dataset\download_real_dataset.py
python train_model.py
python app.py
```

The `models/` files are intentionally not preloaded from a synthetic dataset. They are created only after training on the downloaded real-source data.

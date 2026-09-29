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

## Configuration

PhishGuard requires a secret key and does not create a built-in admin password.
Copy `.env.example` to `.env` and provide `SECRET_KEY`, `ADMIN_USERNAME`, and `ADMIN_PASSWORD`. Never commit `.env`.

For local HTTP development, set `SESSION_COOKIE_SECURE=0`. For HTTPS deployments, keep it `1`.

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
set SECRET_KEY=your-random-secret
set ADMIN_USERNAME=admin
set ADMIN_PASSWORD=your-strong-password
python app.py
```

The `models/` files are intentionally not preloaded from a synthetic dataset. They are created only after training on the downloaded real-source data.


## Security hardening

- Environment-only Flask secret and admin bootstrap credentials
- Secure, HttpOnly, SameSite session cookies
- CSRF protection for browser forms
- Rate limits on login and scanning endpoints
- Request-size and input validation
- Generic production error responses
- Security response headers
- SSRF protection against private/non-public scan targets
- Gunicorn production container
- Pytest coverage and GitHub Actions CI

The public scanner intentionally does not probe localhost, RFC1918/private addresses, loopback, link-local, or other non-global IP targets.

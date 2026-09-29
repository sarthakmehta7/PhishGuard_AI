# PhishGuard AI

Real-time phishing URL detection using machine learning plus live security intelligence.

**Authors:** Sarthak Mehta · Prajwal Kumar · Divyansh Yadav

## What it does

PhishGuard combines a 30-feature URL model with live:

- DNS resolution
- TLS/SSL certificate inspection
- HTTP status and security-header checks
- WHOIS/domain-age information
- URL reputation heuristics
- administrator-managed blacklist rules

The application returns a classification of **Safe**, **Suspicious**, or **Phishing**, together with a risk score, probabilities, evidence, and recommendations.

> PhishGuard is a detection aid, not a guarantee. A Safe result does not prove that a website is trustworthy.

## Architecture

```text
Browser
   |
   v
Flask API + Rate Limiting + CSRF
   |
   +---- URL validation
   |
   +---- 30 URL features ----> ML ensemble
   |
   +---- Public-target validation
   |          |
   |          +--> DNS
   |          +--> TLS
   |          +--> HTTP headers
   |          +--> WHOIS
   |
   +---- Blacklist
   |
   v
SQLite ---> Admin dashboard
```

See [architecture](docs/ARCHITECTURE.md), [security model](docs/SECURITY.md), and [ML pipeline](docs/ML.md).

## ML model

The training pipeline uses a soft-voting ensemble:

- Random Forest
- Gradient Boosting
- Logistic Regression
- RobustScaler preprocessing

Training metrics are generated from the actual downloaded dataset. The pipeline records the dataset SHA-256, class distribution, dropped rows, held-out metrics, confusion matrix, cross-validation results, feature importance, model version, and UTC training time.

No synthetic phishing samples are silently generated.

## Security

The production-oriented version includes:

- environment-only Flask secret
- environment-only admin bootstrap credentials
- password hashing
- secure HttpOnly/SameSite session cookies
- CSRF protection for browser forms
- login and scan rate limiting
- input and request-size validation
- admin role enforcement
- protected scan history/statistics
- security response headers
- generic client-facing 500 errors
- SSRF protection for private/non-public scan targets
- redirect destination validation
- SQLite WAL mode and busy timeout
- dependency vulnerability auditing in CI

## Local setup — Windows

### 1. Clone

```powershell
git clone https://github.com/sarthakmehta7/PhishGuard_AI.git
cd PhishGuard_AI
```

### 2. Create the environment

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### 3. Configure secrets

Copy .env.example to .env and set:

```text
SECRET_KEY=<long-random-secret>
ADMIN_USERNAME=<admin-name>
ADMIN_PASSWORD=<strong-password>
SESSION_COOKIE_SECURE=0
FLASK_DEBUG=0
```

For HTTPS production, use SESSION_COOKIE_SECURE=1.

Never commit .env.

### 4. Download real data

```powershell
python dataset\download_real_dataset.py
```

The downloader uses public threat-intelligence/popularity feeds and reports unavailable sources instead of inventing replacement data.

### 5. Train

```powershell
python train_model.py
```

### 6. Run

```powershell
python app.py
```

Open http://127.0.0.1:5000

## One-command Windows launcher

```text
RUN_PHISHGUARD.bat
```

The launcher creates the virtual environment, installs dependencies, downloads the dataset when absent, trains the model when absent, and starts Flask.

## Docker

Build:

```bash
docker build -t phishguard-ai .
```

Run with an environment file:

```bash
docker run --env-file .env -p 5000:5000 phishguard-ai
```

Or use Docker Compose:

```bash
docker compose up --build
```

The image uses Gunicorn rather than Flask's development server.

## API

### Scan

```http
POST /scan
Content-Type: application/json

{"url":"https://example.com"}
```

### Bulk scan

```http
POST /api/bulk-scan
Content-Type: application/json

{"urls":["https://example.com","https://example.org"]}
```

Up to 10 unique URLs are accepted per request. Bulk analysis runs concurrently with a bounded worker pool.

### Health

```http
GET /healthz
```

Returns service and model-load status.

### Model information

```http
GET /api/model-info
```

### Feature explanation

```http
GET /api/features/<url>
```

### Admin

The admin dashboard provides scan statistics, recent history, model feature importance, top detected threats, and blacklist management.

## Testing

```powershell
pip install -r requirements-dev.txt
pytest -q --cov=. --cov-report=term-missing
ruff check .
pip-audit -r requirements.txt
```

GitHub Actions runs linting, dependency auditing, and the test suite on pushes and pull requests.

## Project structure

```text
PhishGuard_AI/
├── app.py
├── train_model.py
├── database/
│   └── db.py
├── dataset/
│   └── download_real_dataset.py
├── models/
├── utils/
│   └── analyzer.py
├── templates/
├── static/
├── tests/
├── docs/
│   ├── ARCHITECTURE.md
│   ├── SECURITY.md
│   └── ML.md
├── .env.example
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── requirements-dev.txt
└── RUN_PHISHGUARD.bat
```

## Limitations

- Live WHOIS availability varies by registrar and network.
- Reputation heuristics are not the same as an authoritative reputation service.
- Model metrics depend on the downloaded dataset and can drift over time.
- Server-side live checks are deliberately restricted to public network targets.
- The SQLite setup is appropriate for a student/small deployment; a high-volume deployment should move persistence and rate-limit storage to managed services.

## Roadmap

- Calibrated risk thresholds
- Model registry/version rollback
- Explainable prediction UI
- CSV batch upload
- External reputation integrations
- Browser extension
- Persistent production database
- Monitoring and false-positive/false-negative review workflow

## Credits

Made by **Sarthak Mehta, Prajwal Kumar, Divyansh Yadav**.

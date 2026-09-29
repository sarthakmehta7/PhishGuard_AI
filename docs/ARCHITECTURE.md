# PhishGuard AI Architecture

## Request flow

1. Flask receives a URL scan request.
2. Input length/type checks run before analysis.
3. The analyzer extracts 30 deterministic URL features.
4. The target is checked for public routability before server-side network access.
5. DNS, TLS, HTTP-security-header, and WHOIS checks run with bounded timeouts.
6. The trained ensemble predicts Safe / Suspicious / Phishing.
7. Blacklist rules can override the ML prediction.
8. The result is stored in SQLite and returned as structured JSON.
9. The frontend renders the verdict, probabilities, live checks, findings, and recommendations.

## Components

- app.py: HTTP routes, authentication, rate limiting, API validation.
- utils/analyzer.py: URL features and live security checks.
- train_model.py: reproducible model-training pipeline and metrics.
- database/db.py: SQLite persistence and dashboard statistics.
- templates/: Flask HTML views.
- static/: browser UI and scanner interactions.
- tests/: automated regression/security tests.
- .github/workflows/ci.yml: lint, dependency audit, and tests.
- Dockerfile: Gunicorn production image.

## Trust boundaries

User-supplied URLs are untrusted. The scanner must never use them to reach localhost, private RFC1918 networks, link-local addresses, or other non-global targets. Redirect destinations are checked as well.

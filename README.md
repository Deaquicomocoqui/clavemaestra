# 🔐 ClaveMaestra

A lightweight, cryptographically secure password generator with a clean web UI.  
Built with Python (Flask) and vanilla HTML/CSS/JS — no frontend framework required.

![Python](https://img.shields.io/badge/python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/flask-3.x-lightgrey)
![License](https://img.shields.io/badge/license-MIT-green)

---

## Features

- **Cryptographically secure** — uses Python's `secrets` module (CSPRNG), not `random`
- **Configurable constraints** — set minimum counts for lowercase, uppercase, digits, and special characters
- **Entropy scoring** — calculates Shannon entropy (bits) and labels password strength
- **Live strength meter** — visual bar that updates with every generation
- **Copy to clipboard** — one-click copy with toast feedback
- **Responsive UI** — works on desktop and mobile

---

## Screenshot

> Generate strong passwords with live entropy feedback directly in your browser.

---

## Quick Start

### 1. Clone the repository

```bash
git clone https://github.com/your-username/ClaveMaestra.git
cd ClaveMaestra
```

### 2. Create a virtual environment (recommended)

```bash
python -m venv venv
source venv/bin/activate      # macOS / Linux
venv\Scripts\activate         # Windows
```

### 3. Install dependencies

```bash
pip install -r requirements.txt
```

### 4. Run the app

```bash
python app.py
```

Open your browser at **http://127.0.0.1:5000**

---

## Running Tests

```bash
pytest tests/ -v
```

All tests are in `tests/test_app.py` and cover:
- Password length and character class minimums
- Entropy calculation
- Strength labelling
- Flask route responses (200, 400 error cases)

---

## Project Structure

```
ClaveMaestra/
├── app.py                 # Flask application & password logic
├── requirements.txt       # Python dependencies
├── templates/
│   └── index.html         # Single-page frontend
└── tests/
    └── test_app.py        # pytest test suite
```

---

## API

### `POST /generate`

**Request body (JSON):**

| Field           | Type | Default | Description                    |
|-----------------|------|---------|--------------------------------|
| `length`        | int  | 16      | Total password length (8–128)  |
| `min_lowercase` | int  | 1       | Minimum lowercase characters   |
| `min_uppercase` | int  | 1       | Minimum uppercase characters   |
| `min_digits`    | int  | 1       | Minimum digit characters       |
| `min_special`   | int  | 1       | Minimum special characters     |

**Success response (200):**

```json
{
  "password": "g$T3kLmP!nQ9rX2s",
  "stats": {
    "length": 16,
    "lowercase": 7,
    "uppercase": 4,
    "digits": 2,
    "special": 3,
    "entropy": 104.29,
    "strength": { "label": "Very Strong", "color": "#38a169" }
  }
}
```

**Error response (400):**

```json
{ "error": "Total minimum requirements exceed password length." }
```

---

## Security Notes

- Passwords are generated server-side using [`secrets.choice`](https://docs.python.org/3/library/secrets.html), which is backed by the OS CSPRNG.
- The app does **not** log, store, or transmit generated passwords.
- Run behind a reverse proxy (e.g. nginx) with HTTPS in production. Do **not** run with `debug=True` in production.

---

## License

[MIT](LICENSE)
# clavemaestra

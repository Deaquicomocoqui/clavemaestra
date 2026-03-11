"""
Clave Maestra — Enterprise Password Generator
A Flask web application for generating cryptographically secure passwords.

Supports both local development and enterprise/LAN deployment.
Bind address and port are controlled via environment variables:
  HOST  (default: 0.0.0.0  — accessible to all network peers)
  PORT  (default: 5000)

Quick start:
  python app.py                        # LAN mode — share your IP with coworkers
  HOST=127.0.0.1 python app.py         # local-only mode
  PORT=8080 python app.py              # custom port
"""

import os
import socket
import secrets
import string
import math
from flask import Flask, render_template, request, jsonify

app = Flask(__name__)

SPECIAL_CHARS = '!@#$%^&*()_+-=[]{}|;:,.<>?'
MIN_PASSWORD_LENGTH = 8
MAX_PASSWORD_LENGTH = 128


# ── CORS / clipboard helper ────────────────────────────────────────────────────
# Browsers block navigator.clipboard on non-HTTPS pages *unless* the origin is
# localhost. To let coworkers on the LAN copy passwords we add the
# Permissions-Policy header and ensure CORS is permissive for same-LAN origins.
@app.after_request
def add_security_headers(response):
    # Allow clipboard-write from any same-origin context (needed for LAN HTTP)
    response.headers['Permissions-Policy'] = 'clipboard-write=(self)'
    # Prevent clickjacking
    response.headers['X-Frame-Options'] = 'SAMEORIGIN'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response


def calculate_entropy(password: str) -> float:
    """Calculate the entropy (bits) of a password."""
    charset_size = 0
    if any(c in string.ascii_lowercase for c in password):
        charset_size += 26
    if any(c in string.ascii_uppercase for c in password):
        charset_size += 26
    if any(c in string.digits for c in password):
        charset_size += 10
    if any(c in SPECIAL_CHARS for c in password):
        charset_size += len(SPECIAL_CHARS)
    if charset_size == 0:
        return 0.0
    return round(len(password) * math.log2(charset_size), 2)


def get_strength_label(entropy: float) -> dict:
    """Return a strength label and color based on entropy bits."""
    if entropy < 40:
        return {"label": "Weak", "color": "#e53e3e"}
    elif entropy < 60:
        return {"label": "Fair", "color": "#dd6b20"}
    elif entropy < 80:
        return {"label": "Strong", "color": "#d69e2e"}
    else:
        return {"label": "Very Strong", "color": "#38a169"}


def generate_password(
    length: int,
    min_lowercase: int,
    min_uppercase: int,
    min_digits: int,
    min_special: int,
) -> tuple[str | None, dict | str]:
    """
    Generate a cryptographically secure random password.

    Uses `secrets` module (CSPRNG) instead of `random` for security.
    Returns (password, stats_dict) on success, or (None, error_message) on failure.
    """
    total_required = min_lowercase + min_uppercase + min_digits + min_special
    if total_required > length:
        return None, "Total minimum requirements exceed password length."

    if length < MIN_PASSWORD_LENGTH or length > MAX_PASSWORD_LENGTH:
        return None, f"Password length must be between {MIN_PASSWORD_LENGTH} and {MAX_PASSWORD_LENGTH}."

    password_chars: list[str] = []

    # Guarantee minimums using cryptographically secure choices
    password_chars += [secrets.choice(string.ascii_lowercase) for _ in range(min_lowercase)]
    password_chars += [secrets.choice(string.ascii_uppercase) for _ in range(min_uppercase)]
    password_chars += [secrets.choice(string.digits) for _ in range(min_digits)]
    password_chars += [secrets.choice(SPECIAL_CHARS) for _ in range(min_special)]

    # Fill remainder from full charset
    full_charset = string.ascii_lowercase + string.ascii_uppercase + string.digits + SPECIAL_CHARS
    remaining = length - len(password_chars)
    password_chars += [secrets.choice(full_charset) for _ in range(remaining)]

    # Shuffle securely
    secrets.SystemRandom().shuffle(password_chars)

    password = ''.join(password_chars)
    entropy = calculate_entropy(password)

    stats = {
        'length': len(password),
        'lowercase': sum(1 for c in password if c in string.ascii_lowercase),
        'uppercase': sum(1 for c in password if c in string.ascii_uppercase),
        'digits': sum(1 for c in password if c in string.digits),
        'special': sum(1 for c in password if c in SPECIAL_CHARS),
        'entropy': entropy,
        'strength': get_strength_label(entropy),
    }

    return password, stats


@app.route('/')
def index():
    return render_template('index.html')


@app.route('/generate', methods=['POST'])
def generate():
    try:
        data = request.get_json(force=True)
        if not data:
            return jsonify({'error': 'Invalid JSON payload.'}), 400

        length = int(data.get('length', 16))
        min_lowercase = int(data.get('min_lowercase', 1))
        min_uppercase = int(data.get('min_uppercase', 1))
        min_digits = int(data.get('min_digits', 1))
        min_special = int(data.get('min_special', 1))

        password, result = generate_password(
            length, min_lowercase, min_uppercase, min_digits, min_special
        )

        if password is None:
            return jsonify({'error': result}), 400

        return jsonify({'password': password, 'stats': result})

    except (ValueError, TypeError) as e:
        return jsonify({'error': f'Invalid input: {e}'}), 400
    except Exception as e:
        return jsonify({'error': 'An unexpected error occurred.'}), 500


def get_local_ip() -> str:
    """Best-effort LAN IP detection (does not require internet access)."""
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"


if __name__ == '__main__':
    host = os.environ.get('HOST', '0.0.0.0')
    port = int(os.environ.get('PORT', 5000))
    debug = os.environ.get('DEBUG', 'false').lower() == 'true'

    local_ip = get_local_ip()
    display_host = local_ip if host == '0.0.0.0' else host

    print("\n🔐  Clave Maestra — Enterprise Password Generator")
    print("=" * 54)
    print(f"  Local access  → http://127.0.0.1:{port}")
    if host == '0.0.0.0':
        print(f"  Network access → http://{display_host}:{port}  ← share with coworkers")
    print(f"  Debug mode    : {'ON  ⚠️  (not for production)' if debug else 'OFF'}")
    print("  Press CTRL+C to stop.")
    print("=" * 54 + "\n")

    app.run(host=host, port=port, debug=debug)

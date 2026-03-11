"""
Tests for ClaveMaestra password generator logic.
Run with: pytest tests/
"""

import string
import pytest
from app import app, generate_password, calculate_entropy, get_strength_label, SPECIAL_CHARS


# ── Unit tests: generate_password ─────────────────────────────────────────────

class TestGeneratePassword:

    def test_returns_correct_length(self):
        pw, stats = generate_password(20, 2, 2, 2, 2)
        assert len(pw) == 20

    def test_meets_minimum_lowercase(self):
        pw, stats = generate_password(16, 4, 0, 0, 0)
        assert stats['lowercase'] >= 4

    def test_meets_minimum_uppercase(self):
        pw, stats = generate_password(16, 0, 4, 0, 0)
        assert stats['uppercase'] >= 4

    def test_meets_minimum_digits(self):
        pw, stats = generate_password(16, 0, 0, 4, 0)
        assert stats['digits'] >= 4

    def test_meets_minimum_special(self):
        pw, stats = generate_password(16, 0, 0, 0, 4)
        assert stats['special'] >= 4

    def test_all_zeros_still_generates(self):
        pw, stats = generate_password(12, 0, 0, 0, 0)
        assert len(pw) == 12

    def test_requirements_exceed_length_returns_error(self):
        pw, msg = generate_password(8, 4, 4, 4, 4)
        assert pw is None
        assert "exceed" in msg.lower()

    def test_stats_sum_equals_length(self):
        pw, stats = generate_password(24, 2, 2, 2, 2)
        total = stats['lowercase'] + stats['uppercase'] + stats['digits'] + stats['special']
        assert total == stats['length']

    def test_entropy_is_positive(self):
        pw, stats = generate_password(16, 1, 1, 1, 1)
        assert stats['entropy'] > 0

    def test_strength_key_present(self):
        pw, stats = generate_password(16, 1, 1, 1, 1)
        assert 'label' in stats['strength']
        assert 'color' in stats['strength']

    def test_only_valid_characters(self):
        allowed = set(string.ascii_lowercase + string.ascii_uppercase + string.digits + SPECIAL_CHARS)
        for _ in range(10):
            pw, _ = generate_password(32, 2, 2, 2, 2)
            assert all(c in allowed for c in pw)

    def test_invalid_length_too_large(self):
        pw, msg = generate_password(200, 0, 0, 0, 0)
        assert pw is None

    def test_invalid_length_zero(self):
        pw, msg = generate_password(0, 0, 0, 0, 0)
        assert pw is None


# ── Unit tests: calculate_entropy ─────────────────────────────────────────────

class TestCalculateEntropy:

    def test_longer_password_higher_entropy(self):
        short, _ = generate_password(8, 1, 1, 1, 1)
        long_, _ = generate_password(32, 1, 1, 1, 1)
        assert calculate_entropy(long_) > calculate_entropy(short)

    def test_empty_string_returns_zero(self):
        assert calculate_entropy('') == 0.0

    def test_only_lowercase_uses_26_charset(self):
        e = calculate_entropy('abcdefghij')
        assert e == round(10 * __import__('math').log2(26), 2)


# ── Unit tests: get_strength_label ────────────────────────────────────────────

class TestGetStrengthLabel:

    def test_weak_below_40(self):
        assert get_strength_label(30)['label'] == 'Weak'

    def test_fair_between_40_and_60(self):
        assert get_strength_label(50)['label'] == 'Fair'

    def test_strong_between_60_and_80(self):
        assert get_strength_label(70)['label'] == 'Strong'

    def test_very_strong_above_80(self):
        assert get_strength_label(90)['label'] == 'Very Strong'


# ── Flask route tests ──────────────────────────────────────────────────────────

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.test_client() as c:
        yield c


class TestRoutes:

    def test_index_returns_200(self, client):
        resp = client.get('/')
        assert resp.status_code == 200

    def test_generate_valid_request(self, client):
        payload = dict(length=16, min_lowercase=1, min_uppercase=1, min_digits=1, min_special=1)
        resp = client.post('/generate', json=payload)
        assert resp.status_code == 200
        data = resp.get_json()
        assert 'password' in data
        assert len(data['password']) == 16

    def test_generate_bad_requirements(self, client):
        payload = dict(length=8, min_lowercase=4, min_uppercase=4, min_digits=4, min_special=4)
        resp = client.post('/generate', json=payload)
        assert resp.status_code == 400
        assert 'error' in resp.get_json()

    def test_generate_missing_body(self, client):
        resp = client.post('/generate', data='not json', content_type='text/plain')
        assert resp.status_code == 400

    def test_generate_entropy_in_stats(self, client):
        resp = client.post('/generate', json=dict(length=20, min_lowercase=1, min_uppercase=1, min_digits=1, min_special=1))
        data = resp.get_json()
        assert 'entropy' in data['stats']
        assert 'strength' in data['stats']

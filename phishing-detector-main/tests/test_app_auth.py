"""
tests/test_app_auth.py - Unit tests for CyberForge Application Authentication.
"""

import os
from unittest.mock import patch, MagicMock
from services.app_auth import (
    hash_password,
    verify_password,
    get_admin_credentials,
    verify_admin_login,
    has_google_auth_config,
    is_user_authenticated,
    get_authenticated_user_info,
    DEFAULT_ADMIN_USERNAME,
)


def test_password_hashing_format_and_verification():
    raw_pass = "SecureAdminP@ss2026"
    encoded = hash_password(raw_pass)
    
    # Assert format is pbkdf2:sha256:100000$<salt>$<hash>
    parts = encoded.split("$")
    assert len(parts) == 3
    assert parts[0] == "pbkdf2:sha256:100000"
    assert len(parts[1]) == 32  # 16 bytes salt in hex
    assert len(parts[2]) == 64  # sha256 output 32 bytes in hex

    # Verify correct password succeeds
    assert verify_password(raw_pass, encoded) is True
    # Verify wrong password fails
    assert verify_password("WrongPassword123", encoded) is False
    # Verify corrupted hash fails
    assert verify_password(raw_pass, "invalid:hash:format") is False
    assert verify_password(raw_pass, "") is False


def test_admin_login_verification():
    # Default credentials check
    assert verify_admin_login("admin", "CyberForgeAdmin2026!") is True
    assert verify_admin_login("ADMIN", "CyberForgeAdmin2026!") is True  # Case insensitive username
    assert verify_admin_login("admin", "WrongPassword") is False
    assert verify_admin_login("invalid_user", "CyberForgeAdmin2026!") is False


def test_custom_env_admin_credentials():
    custom_user = "secops_admin"
    custom_pass = "CustomSecOpsPass!99"
    custom_hash = hash_password(custom_pass)

    with patch.dict(os.environ, {"ADMIN_USERNAME": custom_user, "ADMIN_PASSWORD_HASH": custom_hash}):
        username, pwd_hash = get_admin_credentials()
        assert username == custom_user
        assert pwd_hash == custom_hash

        assert verify_admin_login(custom_user, custom_pass) is True
        assert verify_admin_login(custom_user, "WrongPass") is False


def test_has_google_auth_config():
    from collections.abc import Mapping

    class MockAttrDict(Mapping):
        def __init__(self, data):
            self._data = data
        def __getitem__(self, key):
            return self._data[key]
        def __len__(self):
            return len(self._data)
        def __iter__(self):
            return iter(self._data)

    # Standard dict
    with patch("streamlit.secrets", {"auth": {"client_id": "google-id", "client_secret": "google-secret"}}, create=True):
        assert has_google_auth_config() is True

    # Mapping / Streamlit AttrDict type
    mock_secrets = MockAttrDict({"auth": MockAttrDict({"client_id": "google-id", "client_secret": "google-secret"})})
    with patch("streamlit.secrets", mock_secrets, create=True):
        assert has_google_auth_config() is True

    # Missing client_secret
    with patch("streamlit.secrets", {"auth": {"client_id": "google-id"}}, create=True):
        assert has_google_auth_config() is False

    # Empty client_id or whitespace
    with patch("streamlit.secrets", {"auth": {"client_id": "  ", "client_secret": "google-secret"}}, create=True):
        assert has_google_auth_config() is False

    # Empty auth dict
    with patch("streamlit.secrets", {"auth": {}}, create=True):
        assert has_google_auth_config() is False

    # Missing auth section
    with patch("streamlit.secrets", {}, create=True):
        assert has_google_auth_config() is False


def test_is_user_authenticated_local_admin():
    import streamlit as st
    st.session_state["authenticated_admin"] = True
    st.session_state["admin_user"] = "admin"
    assert is_user_authenticated() is True
    user_info = get_authenticated_user_info()
    assert user_info["type"] == "admin"
    assert "admin" in user_info["name"]

    st.session_state["authenticated_admin"] = False
    assert is_user_authenticated() is False
    user_info = get_authenticated_user_info()
    assert user_info["type"] == "anonymous"

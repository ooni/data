import time
import jwt
import pytest
import httpx
import os


@pytest.fixture
def client():
    with httpx.Client(base_url=os.environ.get("API_URL"), timeout=10.0) as client:
        yield client

def create_jwt(payload: dict) -> str:
    return jwt.encode(payload, "super_secure", algorithm="HS256")


def create_session_token(account_id: str, role: str) -> str:
    now = int(time.time())
    payload = {
        "nbf": now,
        "iat": now,
        "exp": now + 10 * 86400,
        "aud": "user_auth",
        "account_id": account_id,
        "login_time": None,
        "role": role,
    }
    return create_jwt(payload)


@pytest.fixture
def client_with_user_role(client):
    jwt_token = create_session_token("0" * 16, "user")
    client.headers = {"Authorization": f"Bearer {jwt_token}"}
    yield client


@pytest.fixture
def client_with_admin_role(client):
    jwt_token = create_session_token("0" * 16, "admin")
    client.headers = {"Authorization": f"Bearer {jwt_token}"}
    yield client


@pytest.fixture
def params_since_and_until_with_two_days():
    return set_since_and_until_params(since="2026-01-01", until="2026-01-02")


@pytest.fixture
def params_since_and_until_with_three_days():
    return set_since_and_until_params(since="2026-01-01", until="2026-01-03")


def set_since_and_until_params(since, until):
    params = {"since": since, "until": until}

    return params

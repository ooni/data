import time
import jwt
import pytest
import httpx
from typing import Optional, Any
import os


class APIClient:
    def __init__(self, base_url: str, timeout: float = 10.0, **kwargs: Any):
        """
        Initialize the API client with a base URL.

        Args:
            base_url: The base URL for all requests (e.g., "http://localhost:8000")
            timeout: Request timeout in seconds (default: 10.0)
            **kwargs: Additional arguments passed to httpx.Client
        """
        self.base_url = base_url.rstrip("/")
        self.client = httpx.Client(base_url=self.base_url, timeout=timeout, **kwargs)

    def get(self, path: str, **kwargs: Any) -> httpx.Response:
        """GET request"""
        return self.client.get(path, **kwargs)

    def post(self, path: str, **kwargs: Any) -> httpx.Response:
        """POST request"""
        return self.client.post(path, **kwargs)

    def put(self, path: str, **kwargs: Any) -> httpx.Response:
        """PUT request"""
        return self.client.put(path, **kwargs)

    def patch(self, path: str, **kwargs: Any) -> httpx.Response:
        """PATCH request"""
        return self.client.patch(path, **kwargs)

    def delete(self, path: str, **kwargs: Any) -> httpx.Response:
        """DELETE request"""
        return self.client.delete(path, **kwargs)

    def head(self, path: str, **kwargs: Any) -> httpx.Response:
        """HEAD request"""
        return self.client.head(path, **kwargs)

    def close(self) -> None:
        """Close the client connection"""
        self.client.close()

    def __enter__(self):
        """Context manager entry"""
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        """Context manager exit"""
        self.close()

@pytest.fixture
def client():
    yield APIClient(os.environ.get("API_URL"))

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
    return set_since_and_until_params(since="2024-11-01", until="2024-11-02")


@pytest.fixture
def params_since_and_until_with_ten_days():
    return set_since_and_until_params(since="2024-11-01", until="2024-11-10")


def set_since_and_until_params(since, until):
    params = {"since": since, "until": until}

    return params

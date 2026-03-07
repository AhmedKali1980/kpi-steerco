import logging
import os
from typing import Any

import requests
from dotenv import load_dotenv

load_dotenv()

log = logging.getLogger(__name__)


class DaliImpactAnalysisClient:
    """Minimal DALI client used to retrieve a bearer token and call DALI APIs."""

    def __init__(self) -> None:
        self.base_url = (os.getenv("DALI_BASE_URL") or "").rstrip("/")
        self.token_url = (os.getenv("SGMARKET_TOKEN_URL") or "").strip()
        self.client_id = (os.getenv("SGCONNECT_CLIENT_ID") or "").strip()
        self.client_secret = (os.getenv("SGCONNECT_CLIENT_SECRET") or "").strip()
        self.scopes = (os.getenv("SGCONNECT_SCOPES") or "").strip()
        self.verify = os.getenv("VERIFY_CA", True)

    def _validate_settings(self) -> None:
        missing = []
        for key, value in {
            "DALI_BASE_URL": self.base_url,
            "SGMARKET_TOKEN_URL": self.token_url,
            "SGCONNECT_CLIENT_ID": self.client_id,
            "SGCONNECT_CLIENT_SECRET": self.client_secret,
            "SGCONNECT_SCOPES": self.scopes,
        }.items():
            if not value:
                missing.append(key)

        if missing:
            raise ValueError(f"Missing DALI settings in .env: {', '.join(missing)}")

    def get_access_token(self) -> str:
        """Fetch OAuth2 token from SGConnect/SGMarkets token endpoint."""
        self._validate_settings()
        payload = {
            "grant_type": "client_credentials",
            "client_id": self.client_id,
            "client_secret": self.client_secret,
            "scope": self.scopes,
        }
        headers = {"Content-Type": "application/x-www-form-urlencoded"}
        response = requests.post(
            self.token_url,
            data=payload,
            headers=headers,
            timeout=30,
            verify=self.verify,
        )
        response.raise_for_status()
        body = response.json()
        token = body.get("access_token")
        if not token:
            raise RuntimeError("No access_token found in OAuth2 response")
        return token

    def call_api(self, endpoint: str, method: str = "GET", params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Call a DALI endpoint using bearer token authentication."""
        token = self.get_access_token()
        url = f"{self.base_url}/{endpoint.lstrip('/')}"
        headers = {
            "Authorization": f"Bearer {token}",
            "Accept": "application/json",
        }
        response = requests.request(
            method=method.upper(),
            url=url,
            params=params,
            headers=headers,
            timeout=60,
            verify=self.verify,
        )
        response.raise_for_status()
        return response.json()

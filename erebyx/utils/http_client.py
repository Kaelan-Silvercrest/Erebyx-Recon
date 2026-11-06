"""HTTP client sederhana dengan timeout, identitas jelas, dan rate limit."""

import time
from typing import Any

import requests

DEFAULT_TIMEOUT = 10  # detik
DEFAULT_HEADERS = {"User-Agent": "Erebyx/1.0 (public-data research)"}


class HttpClient:
    def __init__(self, rate_limit_seconds: float = 1.0):
        self.session = requests.Session()
        self.rate_limit_seconds = rate_limit_seconds
        self._last_request_time: float = 0.0

    def _respect_rate_limit(self) -> None:
        now = time.monotonic()
        elapsed = now - self._last_request_time
        wait = self.rate_limit_seconds - elapsed
        if wait > 0:
            time.sleep(wait)
        self._last_request_time = time.monotonic()

    def get(self, url: str, **kwargs: Any) -> requests.Response:
        self._respect_rate_limit()
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        kwargs["headers"] = {**DEFAULT_HEADERS, **kwargs.get("headers", {})}
        return self.session.get(url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> requests.Response:
        self._respect_rate_limit()
        kwargs.setdefault("timeout", DEFAULT_TIMEOUT)
        kwargs["headers"] = {**DEFAULT_HEADERS, **kwargs.get("headers", {})}
        return self.session.post(url, **kwargs)

"""Shared fixtures: the proxy's address, a proxy key, and the requests the simulator recorded."""

import json
import os
import time

import pytest
import requests

PROXY = os.environ.get("PROXY_URL", "http://proxy:8080")
SIM = os.environ.get("SIM_URL", "http://sim:8000")
BOOTSTRAP = os.environ["BOOTSTRAP_API_KEY"]
OLLAMA_MODEL = os.environ.get("OLLAMA_MODEL", "qwen2.5:0.5b")
OLLAMA_EMBED_MODEL = os.environ.get("OLLAMA_EMBED_MODEL", "all-minilm:22m")

# Invented values. The default policy replaces them with these tags.
SSN = "123-45-6789"
EMAIL = "jane.doe@example.com"
PROMPT = f"Customer SSN {SSN}, email {EMAIL}. Summarize the account."
REDACTED_SSN = "{{{REDACTED-ssn}}}"
REDACTED_EMAIL = "{{{REDACTED-email-address}}}"


def assert_redacted(text):
    """No original value remains, and at least one was replaced."""
    assert SSN not in text and "6789" not in text, text
    assert EMAIL not in text and "jane.doe" not in text, text
    assert REDACTED_SSN in text or REDACTED_EMAIL in text, text


def assert_no_originals(text):
    """For a real model's output, which may say anything: the original values, as sent or with spaces for the SSN's
    dashes, must not appear. Undashed digits and fragments such as "6789" are not checked, since the model invents
    numbers (it has answered "1234567890"); that the model never saw the originals is checked on the request."""
    assert SSN not in text and SSN.replace("-", " ") not in text and "45-6789" not in text, text
    assert EMAIL not in text and "jane.doe" not in text, text


@pytest.fixture(scope="session")
def proxy_key():
    for _ in range(120):
        try:
            if requests.get(f"{PROXY}/readyz", timeout=2).status_code == 200:
                break
        except requests.RequestException:
            pass
        time.sleep(1)
    else:
        pytest.fail("the proxy did not become ready")
    response = requests.post(f"{PROXY}/admin/api/keys", headers={"Authorization": f"Bearer {BOOTSTRAP}"},
                             json={"name": "contract-tests", "roles": ["proxy"]}, timeout=10)
    response.raise_for_status()
    return response.json()["key"]


class Recorded:
    """The requests that reached the simulator during one test."""

    def __init__(self):
        requests.post(f"{SIM}/__reset", timeout=5)

    def all(self, provider=None):
        found = requests.get(f"{SIM}/__requests", timeout=5).json()
        return [r for r in found if provider is None or r["provider"] == provider]

    def last(self, provider):
        found = self.all(provider)
        assert found, f"no request reached {provider}"
        return found[-1]

    def last_body_text(self, provider):
        return json.dumps(self.last(provider)["body"])


@pytest.fixture
def recorded():
    return Recorded()


@pytest.fixture(autouse=True)
def proxy_key_is_never_forwarded(proxy_key):
    yield
    for r in requests.get(f"{SIM}/__requests", timeout=5).json():
        assert "x-philter-proxy-key" not in r["headers"], r["path"]
        assert proxy_key not in json.dumps(r["headers"]), r["path"]

"""A real Ollama server, through the proxy, with the ollama Python SDK and with the OpenAI SDK against Ollama's
OpenAI-compatible API (configured as the OpenAI-compatible provider "local"). The simulator records each request on
its way to Ollama."""

import json

import ollama
import openai
import pytest

from conftest import OLLAMA_EMBED_MODEL, OLLAMA_MODEL, PROMPT, PROXY, assert_no_originals, assert_redacted

ECHO = f"Repeat this text exactly: {PROMPT}"


@pytest.fixture
def client(proxy_key):
    return ollama.Client(host=PROXY, headers={"x-philter-proxy-key": proxy_key})


@pytest.fixture
def compatible(proxy_key):
    return openai.OpenAI(base_url=f"{PROXY}/local/v1", api_key="ollama", default_headers={"x-philter-proxy-key": proxy_key})


def test_chat(client, recorded):
    response = client.chat(model=OLLAMA_MODEL, messages=[{"role": "user", "content": ECHO}], stream=False)
    assert_redacted(recorded.last_body_text("ollama"))
    assert response.message.content
    assert_no_originals(response.message.content)


def test_chat_stream(client, recorded):
    text = "".join(part.message.content for part in client.chat(model=OLLAMA_MODEL, messages=[{"role": "user", "content": ECHO}], stream=True))
    assert_redacted(recorded.last_body_text("ollama"))
    assert text
    assert_no_originals(text)


def test_generate(client, recorded):
    response = client.generate(model=OLLAMA_MODEL, prompt=ECHO, system=f"Notes: {PROMPT}", stream=False)
    assert_redacted(recorded.last_body_text("ollama"))
    assert response.response
    assert_no_originals(response.response)
    # The token IDs of the conversation decode to its text, so they are removed.
    assert not response.context


def test_generate_stream(client, recorded):
    text = "".join(part.response for part in client.generate(model=OLLAMA_MODEL, prompt=ECHO, stream=True))
    assert_redacted(recorded.last_body_text("ollama"))
    assert_no_originals(text)


def test_list_models(client, recorded):
    assert OLLAMA_MODEL in [m.model for m in client.list().models]


def test_show(client, recorded):
    # Model metadata carries no conversation text, so it is forwarded unchanged.
    response = client.show(OLLAMA_MODEL)
    assert recorded.last("ollama")["path"] == "/api/show"
    assert "completion" in response.capabilities


def test_embed(client, recorded):
    response = client.embed(model=OLLAMA_EMBED_MODEL, input=[PROMPT, f"Notes: {PROMPT}"])
    sent = recorded.last("ollama")
    assert sent["path"] == "/api/embed"
    assert_redacted(json.dumps(sent["body"]))
    assert len(response.embeddings) == 2 and response.embeddings[0]


def test_embeddings_legacy(client, recorded):
    response = client.embeddings(model=OLLAMA_EMBED_MODEL, prompt=PROMPT)
    sent = recorded.last("ollama")
    assert sent["path"] == "/api/embeddings"
    assert_redacted(json.dumps(sent["body"]))
    assert response.embedding


def test_pull_through_a_forwarding_route(client, recorded):
    # proxy.yaml forwards /api/pull, with scanning on: the progress stream reaches the client unchanged.
    statuses = [progress.status for progress in client.pull(OLLAMA_MODEL, stream=True)]
    assert recorded.last("ollama")["path"] == "/api/pull"
    assert statuses and statuses[-1] == "success", statuses


def test_delete_through_a_forwarding_route(client, recorded):
    # A model that does not exist: Ollama's own 404 shows the request was forwarded, not refused by the proxy.
    with pytest.raises(ollama.ResponseError) as e:
        client.delete("contract-missing:latest")
    assert e.value.status_code == 404, str(e.value)
    assert recorded.last("ollama")["path"] == "/api/delete"


def test_unsupported_endpoint_is_refused(client, recorded):
    # /api/create carries a system prompt the proxy does not redact, so it is refused by default.
    with pytest.raises(ollama.ResponseError) as e:
        client.create(model="contract-copy", from_=OLLAMA_MODEL, system=PROMPT)
    assert e.value.status_code == 400
    assert "unsupported_endpoint" in str(e.value)


def test_openai_compatible_chat(compatible, recorded):
    response = compatible.chat.completions.create(model=OLLAMA_MODEL, messages=[{"role": "user", "content": ECHO}])
    sent = recorded.last("ollama")
    assert sent["path"] == "/v1/chat/completions"
    assert_redacted(json.dumps(sent["body"]))
    assert_no_originals(response.choices[0].message.content)


def test_openai_compatible_chat_stream(compatible, recorded):
    stream = compatible.chat.completions.create(model=OLLAMA_MODEL, messages=[{"role": "user", "content": ECHO}], stream=True)
    text = "".join(chunk.choices[0].delta.content or "" for chunk in stream if chunk.choices)
    assert_redacted(recorded.last_body_text("ollama"))
    assert text
    assert_no_originals(text)

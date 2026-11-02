"""The Anthropic Python SDK through the proxy."""

import json

import anthropic
import pytest

from conftest import PROMPT, PROXY, assert_redacted

MODEL = "claude-sonnet-5-5"
TOOLS = [{"name": "lookup_customer", "description": "Find a customer.",
          "input_schema": {"type": "object", "properties": {"email": {"type": "string"}}}}]


@pytest.fixture
def client(proxy_key):
    return anthropic.Anthropic(base_url=PROXY, api_key="sk-ant-contract-test", default_headers={"x-philter-proxy-key": proxy_key})


def test_messages(client, recorded):
    message = client.messages.create(model=MODEL, max_tokens=100, system=f"Account notes: {PROMPT}",
                                     messages=[{"role": "user", "content": PROMPT}])
    sent = recorded.last("anthropic")
    # The SDK sends its key as a bearer token; either header reaches Anthropic unchanged.
    headers = sent["headers"]
    assert "sk-ant-contract-test" in (headers.get("x-api-key", ""), headers.get("authorization", "").removeprefix("Bearer ")), headers
    assert_redacted(json.dumps(sent["body"]))
    assert_redacted(message.content[0].text)


def test_messages_stream(client, recorded):
    with client.messages.stream(model=MODEL, max_tokens=100, messages=[{"role": "user", "content": PROMPT}]) as stream:
        text = "".join(stream.text_stream)
        final = stream.get_final_message()
    assert_redacted(recorded.last_body_text("anthropic"))
    assert_redacted(text)
    assert_redacted(final.content[0].text)


def test_tool_use(client, recorded):
    message = client.messages.create(model=MODEL, max_tokens=100, tools=TOOLS, messages=[{"role": "user", "content": PROMPT}])
    assert message.content[0].type == "tool_use"
    assert_redacted(json.dumps(message.content[0].input))


def test_tool_use_stream(client, recorded):
    with client.messages.stream(model=MODEL, max_tokens=100, tools=TOOLS, messages=[{"role": "user", "content": PROMPT}]) as stream:
        final = stream.get_final_message()
    assert final.content[0].type == "tool_use"
    assert_redacted(json.dumps(final.content[0].input))


def test_count_tokens(client, recorded):
    assert client.messages.count_tokens(model=MODEL, messages=[{"role": "user", "content": PROMPT}]).input_tokens == 12
    assert_redacted(recorded.last_body_text("anthropic"))


def test_message_batch(client, recorded):
    batch = client.messages.batches.create(requests=[
        {"custom_id": "a", "params": {"model": MODEL, "max_tokens": 100, "messages": [{"role": "user", "content": PROMPT}]}},
        {"custom_id": "b", "params": {"model": MODEL, "max_tokens": 100, "system": PROMPT,
                                      "messages": [{"role": "user", "content": "Hello"}]}}])
    assert batch.id == "msgbatch_1"
    assert_redacted(recorded.last_body_text("anthropic"))


def test_an_image_is_refused(client, recorded):
    with pytest.raises(anthropic.BadRequestError) as e:
        client.messages.create(model=MODEL, max_tokens=100, messages=[{"role": "user", "content": [
            {"type": "image", "source": {"type": "base64", "media_type": "image/png", "data": "iVBORw0KGgo="}}]}])
    assert "media_not_allowed" in str(e.value)
    assert not recorded.all("anthropic")

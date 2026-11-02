"""The OpenAI Python SDK, and its Azure OpenAI client, through the proxy."""

import json

import openai
import pytest

from conftest import PROMPT, PROXY, assert_no_originals, assert_redacted

TOOLS = [{"type": "function", "function": {"name": "lookup_customer", "description": "Find a customer.",
                                           "parameters": {"type": "object", "properties": {"email": {"type": "string"}}}}}]


@pytest.fixture
def client(proxy_key):
    return openai.OpenAI(base_url=f"{PROXY}/v1", api_key="sk-contract-test", default_headers={"x-philter-proxy-key": proxy_key})


@pytest.fixture
def azure(proxy_key):
    return openai.AzureOpenAI(azure_endpoint=PROXY, api_key="azure-contract-test", api_version="2024-10-21",
                              default_headers={"x-philter-proxy-key": proxy_key})


def test_chat(client, recorded):
    response = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": PROMPT}])
    assert_redacted(recorded.last_body_text("openai"))
    assert recorded.last("openai")["headers"]["authorization"] == "Bearer sk-contract-test"
    assert_redacted(response.choices[0].message.content)


def test_chat_stream(client, recorded):
    stream = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": PROMPT}], stream=True)
    text = "".join(chunk.choices[0].delta.content or "" for chunk in stream if chunk.choices)
    assert_redacted(recorded.last_body_text("openai"))
    assert_redacted(text)


def test_chat_tool_call(client, recorded):
    response = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": PROMPT}], tools=TOOLS)
    arguments = json.loads(response.choices[0].message.tool_calls[0].function.arguments)
    assert_redacted(json.dumps(arguments))


def test_chat_tool_call_stream(client, recorded):
    stream = client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": PROMPT}],
                                            tools=TOOLS, stream=True)
    arguments = ""
    for chunk in stream:
        for call in (chunk.choices[0].delta.tool_calls or []) if chunk.choices else []:
            arguments += call.function.arguments or ""
    assert_redacted(json.dumps(json.loads(arguments)))


def test_chat_with_an_image_is_refused(client, recorded):
    with pytest.raises(openai.BadRequestError) as e:
        client.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": [
            {"type": "text", "text": "Describe this."},
            {"type": "image_url", "image_url": {"url": "https://example.com/receipt.png"}}]}])
    assert e.value.body["code"] == "media_not_allowed"
    assert not recorded.all("openai")


def test_responses(client, recorded):
    response = client.responses.create(model="gpt-4o-mini", input=PROMPT, instructions="Be brief.")
    assert_redacted(recorded.last_body_text("openai"))
    assert_redacted(response.output_text)


def test_responses_stream(client, recorded):
    deltas, final = "", None
    for event in client.responses.create(model="gpt-4o-mini", input=PROMPT, stream=True):
        if event.type == "response.output_text.delta":
            deltas += event.delta
        elif event.type == "response.completed":
            final = event.response
    assert_redacted(deltas)
    assert final is not None
    assert_redacted(final.output_text)


def test_embeddings(client, recorded):
    response = client.embeddings.create(model="text-embedding-3-small", input=PROMPT)
    assert_redacted(recorded.last_body_text("openai"))
    assert len(response.data[0].embedding) == 3


def test_models_list(client, recorded):
    assert [m.id for m in client.models.list()] == ["gpt-4o-mini"]


def test_an_endpoint_the_proxy_cannot_redact_is_refused(client, recorded):
    with pytest.raises(openai.BadRequestError) as e:
        client.batches.create(input_file_id="file-contract", endpoint="/v1/chat/completions", completion_window="24h")
    assert e.value.body["code"] == "unsupported_endpoint"
    assert not recorded.all("openai")


def test_azure_chat(azure, recorded):
    response = azure.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": PROMPT}])
    sent = recorded.last("azure")
    assert sent["path"] == "/openai/deployments/gpt-4o-mini/chat/completions"
    assert "api-version=2024-10-21" in sent["query"]
    assert sent["headers"]["api-key"] == "azure-contract-test"
    assert_redacted(json.dumps(sent["body"]))
    assert_redacted(response.choices[0].message.content)


def test_azure_chat_stream(azure, recorded):
    stream = azure.chat.completions.create(model="gpt-4o-mini", messages=[{"role": "user", "content": PROMPT}], stream=True)
    text = "".join(chunk.choices[0].delta.content or "" for chunk in stream if chunk.choices)
    assert_no_originals(recorded.last_body_text("azure"))
    assert_redacted(text)

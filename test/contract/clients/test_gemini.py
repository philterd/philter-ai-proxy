"""The Google Gen AI SDK (Gemini Developer API) through the proxy."""

import json

import pytest
from google import genai
from google.genai import types

from conftest import PROMPT, PROXY, assert_redacted

MODEL = "gemini-2.5-flash"


@pytest.fixture
def client(proxy_key):
    return genai.Client(api_key="gemini-contract-test",
                        http_options=types.HttpOptions(base_url=PROXY + "/", headers={"x-philter-proxy-key": proxy_key}))


def test_generate_content(client, recorded):
    response = client.models.generate_content(model=MODEL, contents=PROMPT,
                                              config=types.GenerateContentConfig(system_instruction=f"Notes: {PROMPT}"))
    sent = recorded.last("gemini")
    assert sent["path"] == f"/v1beta/models/{MODEL}:generateContent"
    assert sent["headers"]["x-goog-api-key"] == "gemini-contract-test"
    assert_redacted(json.dumps(sent["body"]))
    assert_redacted(response.text)


def test_generate_content_stream(client, recorded):
    text = "".join(chunk.text or "" for chunk in client.models.generate_content_stream(model=MODEL, contents=PROMPT))
    sent = recorded.last("gemini")
    assert ":streamGenerateContent" in sent["path"] and "alt=sse" in sent["query"]
    assert_redacted(json.dumps(sent["body"]))
    assert_redacted(text)


def test_function_call(client, recorded):
    tool = types.Tool(function_declarations=[types.FunctionDeclaration(
        name="lookup_customer", description="Find a customer.",
        parameters=types.Schema(type="OBJECT", properties={"email": types.Schema(type="STRING")}))])
    response = client.models.generate_content(model=MODEL, contents=PROMPT, config=types.GenerateContentConfig(
        tools=[tool], automatic_function_calling=types.AutomaticFunctionCallingConfig(disable=True)))
    assert_redacted(json.dumps(response.function_calls[0].args))


def test_embed_content(client, recorded):
    response = client.models.embed_content(model="gemini-embedding-001", contents=[PROMPT, f"Notes: {PROMPT}"],
                                           config=types.EmbedContentConfig(task_type="RETRIEVAL_DOCUMENT", title=f"File for {PROMPT}"))
    sent = recorded.last("gemini")
    # The SDK sends embed_content() to batchEmbedContents on the Gemini API.
    assert sent["path"] == "/v1beta/models/gemini-embedding-001:batchEmbedContents", sent["path"]
    assert_redacted(json.dumps(sent["body"]))
    assert len(response.embeddings) == 2 and response.embeddings[0].values


def test_count_tokens(client, recorded):
    response = client.models.count_tokens(model=MODEL, contents=PROMPT)
    sent = recorded.last("gemini")
    assert sent["path"] == f"/v1beta/models/{MODEL}:countTokens"
    assert_redacted(json.dumps(sent["body"]))
    assert response.total_tokens == 12

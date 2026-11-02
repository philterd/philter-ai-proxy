"""boto3's Bedrock Runtime client through the proxy. The simulator checks the proxy's SigV4 signature with botocore."""

import json

import boto3
import pytest

from conftest import PROMPT, PROXY, assert_redacted

# A real model ID shape: its ":" is sent percent-encoded, which the proxy must route, scope, and sign correctly.
MODEL = "anthropic.claude-3-haiku-20240307-v1:0"
TOOL_CONFIG = {"tools": [{"toolSpec": {"name": "lookup_customer", "description": "Find a customer.",
                                       "inputSchema": {"json": {"type": "object", "properties": {"email": {"type": "string"}}}}}}]}


@pytest.fixture
def client(proxy_key):
    bedrock = boto3.client("bedrock-runtime", endpoint_url=PROXY, region_name="us-east-1",
                           aws_access_key_id="AKIDCLIENTONLY", aws_secret_access_key="client-secret-not-used-by-the-proxy")

    def add_proxy_key(request, **kwargs):
        request.headers["x-philter-proxy-key"] = proxy_key

    bedrock.meta.events.register("before-sign.bedrock-runtime.*", add_proxy_key)
    return bedrock


def message():
    return [{"role": "user", "content": [{"text": PROMPT}]}]


def test_converse(client, recorded):
    response = client.converse(modelId=MODEL, messages=message(), system=[{"text": f"Notes: {PROMPT}"}])
    sent = recorded.last("bedrock")
    assert sent["path"] == "/model/anthropic.claude-3-haiku-20240307-v1%3A0/converse"
    # The proxy signs with its own credentials; the client's are not forwarded.
    assert "AKIDCONTRACTTEST/" in sent["headers"]["authorization"]
    assert_redacted(json.dumps(sent["body"]))
    assert_redacted(response["output"]["message"]["content"][0]["text"])


def test_converse_stream(client, recorded):
    response = client.converse_stream(modelId=MODEL, messages=message())
    text = ""
    for event in response["stream"]:
        if "contentBlockDelta" in event:
            text += event["contentBlockDelta"]["delta"].get("text", "")
    assert_redacted(recorded.last_body_text("bedrock"))
    assert_redacted(text)


def test_converse_tool_use(client, recorded):
    response = client.converse(modelId=MODEL, messages=message(), toolConfig=TOOL_CONFIG)
    assert_redacted(json.dumps(response["output"]["message"]["content"][0]["toolUse"]["input"]))


def test_converse_stream_tool_use(client, recorded):
    response = client.converse_stream(modelId=MODEL, messages=message(), toolConfig=TOOL_CONFIG)
    arguments = ""
    for event in response["stream"]:
        if "contentBlockDelta" in event and "toolUse" in event["contentBlockDelta"]["delta"]:
            arguments += event["contentBlockDelta"]["delta"]["toolUse"]["input"]
    assert_redacted(json.dumps(json.loads(arguments)))


# ---- InvokeModel, with Claude's native Messages body

CLAUDE_BODY = {"anthropic_version": "bedrock-2023-05-31", "max_tokens": 100, "system": f"Notes: {PROMPT}",
               "messages": [{"role": "user", "content": PROMPT}]}


def test_invoke_model(client, recorded):
    response = client.invoke_model(modelId=MODEL, body=json.dumps(CLAUDE_BODY))
    sent = recorded.last("bedrock")
    assert sent["path"] == "/model/anthropic.claude-3-haiku-20240307-v1%3A0/invoke"
    assert "AKIDCONTRACTTEST/" in sent["headers"]["authorization"]
    assert_redacted(json.dumps(sent["body"]))
    assert_redacted(json.loads(response["body"].read())["content"][0]["text"])


def test_invoke_model_with_response_stream(client, recorded):
    response = client.invoke_model_with_response_stream(modelId=MODEL, body=json.dumps(CLAUDE_BODY))
    text = ""
    last = None
    for event in response["body"]:
        last = json.loads(event["chunk"]["bytes"])
        if last["type"] == "content_block_delta":
            text += last["delta"]["text"]
    assert_redacted(recorded.last_body_text("bedrock"))
    assert_redacted(text)
    assert last["type"] == "message_stop" and "amazon-bedrock-invocationMetrics" in last


def test_invoke_titan_embeddings(client, recorded):
    response = client.invoke_model(modelId="amazon.titan-embed-text-v2:0", body=json.dumps({"inputText": PROMPT}))
    assert_redacted(recorded.last_body_text("bedrock"))
    assert json.loads(response["body"].read())["embedding"]


def test_invoke_of_another_model_family_is_refused(client, recorded):
    with pytest.raises(client.exceptions.ClientError) as e:
        client.invoke_model(modelId="meta.llama3-8b-instruct-v1:0", body=json.dumps({"prompt": PROMPT}))
    assert "unsupported_endpoint" in str(e.value)
    assert not recorded.all("bedrock")


# ---- The Anthropic SDK's Bedrock client, which uses InvokeModel

@pytest.fixture
def anthropic_bedrock(proxy_key):
    from anthropic import AnthropicBedrock
    return AnthropicBedrock(base_url=PROXY, aws_region="us-east-1", aws_access_key="AKIDCLIENTONLY",
                            aws_secret_key="client-secret-not-used-by-the-proxy", default_headers={"x-philter-proxy-key": proxy_key})


def test_anthropic_bedrock_messages(anthropic_bedrock, recorded):
    message = anthropic_bedrock.messages.create(model=MODEL, max_tokens=100, system=f"Notes: {PROMPT}",
                                                messages=[{"role": "user", "content": PROMPT}])
    sent = recorded.last("bedrock")
    assert sent["path"].endswith("/invoke")
    assert_redacted(json.dumps(sent["body"]))
    assert_redacted(message.content[0].text)


def test_anthropic_bedrock_stream(anthropic_bedrock, recorded):
    with anthropic_bedrock.messages.stream(model=MODEL, max_tokens=100, messages=[{"role": "user", "content": PROMPT}]) as stream:
        text = "".join(stream.text_stream)
    assert recorded.last("bedrock")["path"].endswith("/invoke-with-response-stream")
    assert_redacted(recorded.last_body_text("bedrock"))
    assert_redacted(text)


def test_an_unscannable_stream_ends_with_an_error_the_sdk_raises(client, recorded):
    # A legacy Claude stream cannot be scanned; the proxy ends it with an AWS exception message, which boto3 raises.
    from botocore.exceptions import EventStreamError
    response = client.invoke_model_with_response_stream(
        modelId="anthropic.claude-v2:1", body=json.dumps({"prompt": "\n\nHuman: hi\n\nAssistant:", "max_tokens_to_sample": 5}))
    with pytest.raises(EventStreamError) as e:
        for event in response["body"]:
            assert_redacted(json.dumps(event, default=str))
    assert e.value.response["Error"]["Code"] == "response_unscannable", e.value.response

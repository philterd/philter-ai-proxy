"""Provider simulator for the contract tests.

Serves OpenAI, Azure OpenAI, Anthropic, Gemini, and Bedrock responses shaped as each provider documents them,
under a path prefix per provider (/openai, /azure, /anthropic, /gemini, /bedrock), and passes /ollama/* through to
a real Ollama server. Every request is recorded so the tests can check what reached the "provider".

Responses contain an invented SSN and email address, so the tests can check that response scanning redacts them
and that each SDK still parses what the proxy returns.

    GET  /__requests   the recorded requests, oldest first
    POST /__reset      forgets them
"""

import base64
import binascii
import json
import os
import struct
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import unquote, urlsplit

SSN = "123-45-6789"
EMAIL = "jane.doe@example.com"
REPLY = f"The customer's SSN is {SSN} and their email is {EMAIL}."
OLLAMA = os.environ.get("OLLAMA_URL", "http://ollama:11434")
AWS_ACCESS_KEY = os.environ.get("AWS_ACCESS_KEY_ID", "")
AWS_SECRET_KEY = os.environ.get("AWS_SECRET_ACCESS_KEY", "")

RECORDED = []
LOCK = threading.Lock()


def pieces(text, size=7):
    """The text in small fragments, so values are split across stream events."""
    return [text[i:i + size] for i in range(0, len(text), size)]


def wants_tools(body):
    return bool(body.get("tools") or body.get("toolConfig"))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def log_message(self, fmt, *args):
        pass

    # ---- plumbing

    def body(self):
        length = int(self.headers.get("Content-Length") or 0)
        if self.headers.get("Transfer-Encoding", "").lower() == "chunked":
            data = b""
            while True:
                size = int(self.rfile.readline().strip(), 16)
                if size == 0:
                    self.rfile.readline()
                    break
                data += self.rfile.read(size)
                self.rfile.readline()
            return data
        return self.rfile.read(length) if length else b""

    def send_json(self, value, status=200):
        data = json.dumps(value).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def start_stream(self, content_type):
        self.send_response(200)
        self.send_header("Content-Type", content_type)
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()

    def chunk(self, data):
        if isinstance(data, str):
            data = data.encode()
        self.wfile.write(f"{len(data):x}\r\n".encode() + data + b"\r\n")
        self.wfile.flush()

    def end_stream(self):
        self.wfile.write(b"0\r\n\r\n")
        self.wfile.flush()

    def sse(self, data, event=None):
        self.chunk((f"event: {event}\n" if event else "") + f"data: {json.dumps(data) if not isinstance(data, str) else data}\n\n")

    # ---- dispatch

    def do_GET(self):
        self.handle_request("GET")

    def do_POST(self):
        self.handle_request("POST")

    def do_DELETE(self):
        self.handle_request("DELETE")

    def handle_request(self, method):
        raw = self.body()
        parts = urlsplit(self.path)
        path = parts.path
        if path == "/__requests":
            with LOCK:
                return self.send_json(list(RECORDED))
        if path == "/__reset":
            with LOCK:
                RECORDED.clear()
            return self.send_json({})
        provider, _, rest = path.lstrip("/").partition("/")
        rest = "/" + rest
        try:
            body = json.loads(raw) if raw else {}
        except ValueError:
            body = None
        with LOCK:
            RECORDED.append({"provider": provider, "method": method, "path": rest, "query": parts.query,
                             "headers": {k.lower(): v for k, v in self.headers.items()},
                             "body": body, "raw": raw.decode("utf-8", "replace")})
        if provider == "ollama":
            return self.ollama(method, rest, parts.query, raw)
        if body is None:
            return self.send_json({"error": {"message": "body is not JSON"}}, 400)
        handler = {"openai": self.openai, "azure": self.openai, "anthropic": self.anthropic,
                   "gemini": self.gemini, "bedrock": self.bedrock}.get(provider)
        if handler is None:
            return self.send_json({"error": {"message": f"unknown provider {provider}"}}, 404)
        handler(method, rest, body)

    # ---- OpenAI and Azure OpenAI

    def openai(self, method, path, body):
        model = body.get("model", "gpt-4o-mini")
        created = int(time.time())
        if method == "GET" and path.endswith("/models"):
            return self.send_json({"object": "list", "data": [{"id": "gpt-4o-mini", "object": "model", "created": created, "owned_by": "openai"}]})
        if path.endswith("/chat/completions"):
            return self.chat(body, model, created)
        if path.endswith("/responses"):
            return self.openai_responses(body, model, created)
        if path.endswith("/embeddings"):
            return self.send_json({"object": "list", "model": model,
                                   "data": [{"object": "embedding", "index": 0, "embedding": [0.01, -0.02, 0.03]}],
                                   "usage": {"prompt_tokens": 5, "total_tokens": 5}})
        self.send_json({"error": {"message": f"unsimulated path {path}", "type": "invalid_request_error"}}, 404)

    def chat(self, body, model, created):
        tools = wants_tools(body)
        arguments = json.dumps({"email": EMAIL, "ssn": SSN})
        if not body.get("stream"):
            message = {"role": "assistant", "content": None if tools else REPLY, "refusal": None}
            if tools:
                message["tool_calls"] = [{"id": "call_1", "type": "function",
                                          "function": {"name": body["tools"][0]["function"]["name"], "arguments": arguments}}]
            return self.send_json({"id": "chatcmpl-1", "object": "chat.completion", "created": created, "model": model,
                                   "choices": [{"index": 0, "message": message, "logprobs": None,
                                                "finish_reason": "tool_calls" if tools else "stop"}],
                                   "usage": {"prompt_tokens": 10, "completion_tokens": 12, "total_tokens": 22}})
        self.start_stream("text/event-stream")
        base = {"id": "chatcmpl-1", "object": "chat.completion.chunk", "created": created, "model": model}

        def chunk(delta, finish=None):
            self.sse({**base, "choices": [{"index": 0, "delta": delta, "logprobs": None, "finish_reason": finish}]})

        chunk({"role": "assistant", "content": ""})
        if tools:
            chunk({"tool_calls": [{"index": 0, "id": "call_1", "type": "function",
                                   "function": {"name": body["tools"][0]["function"]["name"], "arguments": ""}}]})
            for piece in pieces(arguments):
                chunk({"tool_calls": [{"index": 0, "function": {"arguments": piece}}]})
            chunk({}, "tool_calls")
        else:
            for piece in pieces(REPLY):
                chunk({"content": piece})
            chunk({}, "stop")
        self.chunk(": keep-alive\n\n")
        self.sse("[DONE]")
        self.end_stream()

    def openai_responses(self, body, model, created):
        message = {"id": "msg_1", "type": "message", "status": "completed", "role": "assistant",
                   "content": [{"type": "output_text", "text": REPLY, "annotations": []}]}
        response = {"id": "resp_1", "object": "response", "created_at": created, "status": "completed", "model": model,
                    "output": [message], "parallel_tool_calls": True, "tool_choice": "auto", "tools": [],
                    "usage": {"input_tokens": 10, "output_tokens": 12, "total_tokens": 22,
                              "input_tokens_details": {"cached_tokens": 0}, "output_tokens_details": {"reasoning_tokens": 0}}}
        if not body.get("stream"):
            return self.send_json(response)
        self.start_stream("text/event-stream")
        seq = iter(range(1000))

        def event(kind, data):
            self.sse({"type": kind, "sequence_number": next(seq), **data}, event=kind)

        in_progress = {**response, "status": "in_progress", "output": [], "usage": None}
        event("response.created", {"response": in_progress})
        event("response.in_progress", {"response": in_progress})
        event("response.output_item.added", {"output_index": 0, "item": {**message, "status": "in_progress", "content": []}})
        event("response.content_part.added", {"item_id": "msg_1", "output_index": 0, "content_index": 0,
                                              "part": {"type": "output_text", "text": "", "annotations": []}})
        for piece in pieces(REPLY):
            event("response.output_text.delta", {"item_id": "msg_1", "output_index": 0, "content_index": 0, "delta": piece})
        event("response.output_text.done", {"item_id": "msg_1", "output_index": 0, "content_index": 0, "text": REPLY})
        event("response.content_part.done", {"item_id": "msg_1", "output_index": 0, "content_index": 0,
                                             "part": {"type": "output_text", "text": REPLY, "annotations": []}})
        event("response.output_item.done", {"output_index": 0, "item": message})
        event("response.completed", {"response": response})
        self.end_stream()

    # ---- Anthropic

    def anthropic(self, method, path, body):
        model = body.get("model", "claude-sonnet-5-5")
        if path == "/v1/messages/count_tokens":
            return self.send_json({"input_tokens": 12})
        if path == "/v1/messages/batches":
            return self.send_json({"id": "msgbatch_1", "type": "message_batch", "processing_status": "in_progress",
                                   "request_counts": {"processing": len(body.get("requests", [])), "succeeded": 0,
                                                      "errored": 0, "canceled": 0, "expired": 0},
                                   "ended_at": None, "created_at": "2026-11-01T00:00:00Z", "expires_at": "2026-11-02T00:00:00Z",
                                   "archived_at": None, "cancel_initiated_at": None, "results_url": None})
        if path != "/v1/messages":
            return self.send_json({"type": "error", "error": {"type": "not_found_error", "message": path}}, 404)
        if not body.get("stream"):
            return self.send_json(claude_message(body, model))
        self.start_stream("text/event-stream")
        for event in claude_events(body, model):
            self.sse(event, event["type"])
        self.end_stream()

    # ---- Gemini

    def gemini(self, method, path, body):
        model = path.rsplit("/", 1)[-1].split(":")[0]
        if path.endswith(":countTokens"):
            return self.send_json({"totalTokens": 12, "promptTokensDetails": [{"modality": "TEXT", "tokenCount": 12}]})
        if path.endswith(":embedContent"):
            return self.send_json({"embedding": {"values": [0.1, 0.2, 0.3]}})
        if path.endswith(":batchEmbedContents"):
            return self.send_json({"embeddings": [{"values": [0.1, 0.2, 0.3]} for _ in body.get("requests", [])]})
        tools = wants_tools(body)
        usage = {"promptTokenCount": 10, "candidatesTokenCount": 12, "totalTokenCount": 22}
        if tools:
            name = body["tools"][0]["functionDeclarations"][0]["name"]
            parts = [{"functionCall": {"name": name, "args": {"email": EMAIL, "ssn": SSN}}}]
        else:
            parts = [{"text": REPLY}]

        def response(parts, finish):
            candidate = {"content": {"role": "model", "parts": parts}, "index": 0}
            if finish:
                candidate["finishReason"] = "STOP"
            return {"candidates": [candidate], "usageMetadata": usage, "modelVersion": model, "responseId": "r1"}

        if ":streamGenerateContent" not in path:
            return self.send_json(response(parts, True))
        self.start_stream("text/event-stream")
        if tools:
            self.chunk(f"data: {json.dumps(response(parts, True))}\r\n\r\n")
        else:
            texts = pieces(REPLY)
            for i, piece in enumerate(texts):
                self.chunk(f"data: {json.dumps(response([{'text': piece}], i == len(texts) - 1))}\r\n\r\n")
        self.end_stream()

    # ---- Bedrock Converse and InvokeModel

    def bedrock(self, method, path, body):
        problem = self.sigv4_problem(method, path)
        if problem:
            return self.send_json({"message": problem}, 403)
        operation = path.rsplit("/", 1)[-1]
        model = unquote(path.split("/")[2])
        if operation in ("invoke", "invoke-with-response-stream"):
            return self.bedrock_invoke(operation, model, body)
        tools = wants_tools(body)
        tool_input = {"email": EMAIL, "ssn": SSN}
        usage = {"inputTokens": 10, "outputTokens": 12, "totalTokens": 22}
        if path.endswith("/converse"):
            content = ([{"toolUse": {"toolUseId": "tooluse_1", "name": body["toolConfig"]["tools"][0]["toolSpec"]["name"],
                                     "input": tool_input}}] if tools else [{"text": REPLY}])
            return self.send_json({"output": {"message": {"role": "assistant", "content": content}},
                                   "stopReason": "tool_use" if tools else "end_turn", "usage": usage, "metrics": {"latencyMs": 5}})
        self.start_stream("application/vnd.amazon.eventstream")
        self.chunk(event_message("messageStart", {"role": "assistant"}))
        if tools:
            name = body["toolConfig"]["tools"][0]["toolSpec"]["name"]
            self.chunk(event_message("contentBlockStart", {"contentBlockIndex": 0,
                                                           "start": {"toolUse": {"toolUseId": "tooluse_1", "name": name}}}))
            for piece in pieces(json.dumps(tool_input)):
                self.chunk(event_message("contentBlockDelta", {"contentBlockIndex": 0, "delta": {"toolUse": {"input": piece}}}))
        else:
            for piece in pieces(REPLY):
                self.chunk(event_message("contentBlockDelta", {"contentBlockIndex": 0, "delta": {"text": piece}}))
        self.chunk(event_message("contentBlockStop", {"contentBlockIndex": 0}))
        self.chunk(event_message("messageStop", {"stopReason": "tool_use" if tools else "end_turn"}))
        self.chunk(event_message("metadata", {"usage": usage, "metrics": {"latencyMs": 5}}))
        self.end_stream()

    def bedrock_invoke(self, operation, model, body):
        if "titan-embed" in model:
            return self.send_json({"embedding": [0.1, 0.2, 0.3], "inputTextTokenCount": 3})
        if "claude-v2" in model and operation == "invoke-with-response-stream":
            # A legacy Text Completions stream, which the proxy cannot scan.
            self.start_stream("application/vnd.amazon.eventstream")
            data = base64.b64encode(json.dumps({"completion": REPLY, "stop_reason": None}).encode()).decode()
            self.chunk(event_message("chunk", {"bytes": data}))
            return self.end_stream()
        if "anthropic." not in model or not body.get("anthropic_version"):
            return self.send_json({"message": f"unexpected invoke body for {model}"}, 400)
        if operation == "invoke":
            return self.send_json(claude_message(body, model))
        self.start_stream("application/vnd.amazon.eventstream")
        for event in claude_events(body, model):
            if event["type"] == "message_stop":
                event["amazon-bedrock-invocationMetrics"] = {"inputTokenCount": 10, "outputTokenCount": 12,
                                                             "invocationLatency": 5, "firstByteLatency": 2}
            data = base64.b64encode(json.dumps(event).encode()).decode()
            self.chunk(event_message("chunk", {"bytes": data, "p": "abcdefgh"}))
        self.end_stream()

    def sigv4_problem(self, method, path):
        """Checks the proxy's SigV4 signature with botocore, AWS's own implementation, from the request as received."""
        from botocore.auth import SigV4Auth
        from botocore.awsrequest import AWSRequest
        from botocore.credentials import Credentials
        authorization = self.headers.get("Authorization", "")
        if not authorization.startswith("AWS4-HMAC-SHA256 "):
            return "missing SigV4 Authorization"
        fields = dict(f.strip().split("=", 1) for f in authorization[len("AWS4-HMAC-SHA256 "):].split(","))
        if not fields["Credential"].startswith(AWS_ACCESS_KEY + "/") or "/us-east-1/bedrock/aws4_request" not in fields["Credential"]:
            return f"unexpected credential scope {fields['Credential']}"
        signed = fields["SignedHeaders"].split(";")
        with LOCK:
            raw = RECORDED[-1]["raw"].encode()
        # Only the headers the proxy signed, so botocore signs the same set.
        headers = {name: self.headers.get(name) for name in signed}
        request = AWSRequest(method=method, url=f"http://{self.headers['Host']}{urlsplit(self.path).path}", data=raw, headers=headers)
        request.context["timestamp"] = self.headers["X-Amz-Date"]
        auth = SigV4Auth(Credentials(AWS_ACCESS_KEY, AWS_SECRET_KEY), "bedrock", "us-east-1")
        canonical = auth.canonical_request(request)
        expected = auth.signature(auth.string_to_sign(request, canonical), request)
        if expected != fields["Signature"]:
            return f"signature mismatch; canonical request was:\n{canonical}"
        return None

    # ---- Ollama: recorded, then passed to the real server

    def ollama(self, method, path, query, raw):
        url = OLLAMA + path + (f"?{query}" if query else "")
        request = urllib.request.Request(url, data=raw if method in ("POST", "DELETE") else None, method=method,
                                         headers={"Content-Type": self.headers.get("Content-Type", "application/json")})
        try:
            upstream = urllib.request.urlopen(request, timeout=600)
        except urllib.error.HTTPError as e:
            upstream = e
        self.send_response(upstream.status if hasattr(upstream, "status") else upstream.code)
        self.send_header("Content-Type", upstream.headers.get("Content-Type", "application/json"))
        self.send_header("Transfer-Encoding", "chunked")
        self.end_headers()
        while True:
            line = upstream.readline()
            if not line:
                break
            self.chunk(line)
        self.end_stream()


def claude_message(body, model):
    """A Messages API response: text, or a tool call when the request offers tools."""
    tools = wants_tools(body)
    content = ([{"type": "tool_use", "id": "toolu_1", "name": body["tools"][0]["name"], "input": {"email": EMAIL, "ssn": SSN}}]
               if tools else [{"type": "text", "text": REPLY}])
    return {"id": "msg_1", "type": "message", "role": "assistant", "model": model, "content": content,
            "stop_reason": "tool_use" if tools else "end_turn", "stop_sequence": None,
            "usage": {"input_tokens": 10, "output_tokens": 12}}


def claude_events(body, model):
    """The Messages API stream's events, in order."""
    tools = wants_tools(body)
    events = [{"type": "message_start", "message": {"id": "msg_1", "type": "message", "role": "assistant", "model": model,
                                                    "content": [], "stop_reason": None, "stop_sequence": None,
                                                    "usage": {"input_tokens": 10, "output_tokens": 1}}}]
    if tools:
        events.append({"type": "content_block_start", "index": 0,
                       "content_block": {"type": "tool_use", "id": "toolu_1", "name": body["tools"][0]["name"], "input": {}}})
        for piece in pieces(json.dumps({"email": EMAIL, "ssn": SSN})):
            events.append({"type": "content_block_delta", "index": 0, "delta": {"type": "input_json_delta", "partial_json": piece}})
    else:
        events.append({"type": "content_block_start", "index": 0, "content_block": {"type": "text", "text": ""}})
        events.append({"type": "ping"})
        for piece in pieces(REPLY):
            events.append({"type": "content_block_delta", "index": 0, "delta": {"type": "text_delta", "text": piece}})
    events.append({"type": "content_block_stop", "index": 0})
    events.append({"type": "message_delta", "delta": {"stop_reason": "tool_use" if tools else "end_turn", "stop_sequence": None},
                   "usage": {"output_tokens": 12}})
    events.append({"type": "message_stop"})
    return events


def event_message(event_type, payload):
    """One AWS event stream message: prelude, headers, JSON payload, and CRC32s."""
    headers = b""
    for name, value in ((":event-type", event_type), (":content-type", "application/json"), (":message-type", "event")):
        n, v = name.encode(), value.encode()
        headers += struct.pack("B", len(n)) + n + b"\x07" + struct.pack(">H", len(v)) + v
    body = json.dumps(payload).encode()
    total = 12 + len(headers) + len(body) + 4
    prelude = struct.pack(">II", total, len(headers))
    prelude += struct.pack(">I", binascii.crc32(prelude) & 0xFFFFFFFF)
    message = prelude + headers + body
    return message + struct.pack(">I", binascii.crc32(message) & 0xFFFFFFFF)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 8000), Handler).serve_forever()

# API Reference

The proxy serves two APIs on port 8080: provider traffic, which it redacts and forwards, and the admin API under `/admin`, for policies and API keys. See [Usage](usage.md) for which path goes to which provider.

## Redacted Fields

The proxy redacts the text-bearing fields of each request before forwarding it. Every other field, such as model names, sampling parameters, tool definitions, and IDs, is forwarded unchanged.

| Provider | Request | Fields redacted |
|---|---|---|
| OpenAI family | Chat completions | Each message's `content` (a string, or the `text` of each content part), `refusal`, `tool_calls[].function.arguments`, and `function_call.arguments` |
| OpenAI family | Responses (`/responses`) | `instructions`; `input` as a string, or each item: message content (a string or `input_text` and `output_text` parts), `function_call.arguments`, `function_call_output.output`, and reasoning summaries |
| OpenAI family | Embeddings, moderations, speech (`/audio/speech`) | `input` (a string or an array of strings; token-ID arrays are left alone) |
| OpenAI family | Image generation, legacy completions | `prompt` (a string or an array of strings) |
| Anthropic | Messages | `system` (a string or text blocks); each message's content (a string, or `text` blocks, `tool_use` input, and `tool_result` content as a string or text blocks) |
| Gemini, Vertex AI | `generateContent`, `streamGenerateContent` | Each part's `text`, `functionCall.args`, and `functionResponse.response`, in `contents` and `systemInstruction` |
| Ollama | `/api/generate` | `prompt`, `system` |
| Ollama | `/api/chat` | Each message's `content`, `thinking`, and `tool_calls[].function.arguments` |
| Bedrock | Converse | `system[].text`; each message's `text` blocks, `toolUse.input`, and `toolResult.content` (text and JSON) |

The OpenAI family is OpenAI, Azure OpenAI, and the OpenAI-compatible providers. Arguments and other JSON held in a string are parsed, each string in them redacted, and the JSON written back; when they are not JSON, the whole string is redacted as text.

Not redacted: Anthropic thinking blocks and Bedrock reasoning blocks sent back in a conversation, since the providers verify their signatures and a changed block is refused.

All the fields of one request are redacted together, against one policy. Without a configured context, a value is replaced the same way in every field of the request and in its response, when the policy's strategy uses `"replacementScope": "CONTEXT"`. See [Contexts](policies.md#contexts).

### Images, audio, and files are not redacted

Only text is redacted. Images, audio, and files embedded in a JSON request are forwarded to the provider unchanged and are not inspected, including any text, faces, or spoken words they contain. That covers, for example:

| Provider | Not redacted |
|----------|--------------|
| OpenAI / OpenAI-compatible / Azure OpenAI | `image_url`, `input_audio`, and `file` content parts; Responses API `input_image` and `input_file` items |
| Anthropic | `image` and `document` content blocks |
| Gemini / Vertex AI | `inlineData` and `fileData` parts |
| Bedrock Converse | `image`, `document`, and `video` content blocks |
| Ollama | `images` |

The same holds for responses: response scanning reads response text only, so generated images and audio, and the transcript that accompanies audio output, are returned unscanned.

If images, audio, or files sent to a provider can contain sensitive data, remove or redact them before the request reaches the proxy, or route those requests elsewhere. Multipart uploads (files, audio transcription, image edits) are refused rather than forwarded; see [Supported request types](#supported-request-types).

## Supported request types

The proxy accepts a JSON request body. **It does not parse `multipart/form-data`.**

| Request type | Behavior | Error |
|---|---|---|
| The requests in the table above | Redacted, then forwarded | - |
| A request without a body, such as `GET /v1/models` | Forwarded unchanged | - |
| Any other request with a JSON body, such as `/v1/batches` | Forwarded unchanged, no redaction | - |
| `/v1/images/edits`, `/v1/images/variations` | **Refused.** Not supported, and not planned | `400` `invalid_request` / `unsupported_content_type` |
| `/v1/files` (uploads) | **Refused.** Not supported, and not planned | `400` `invalid_request` / `unsupported_content_type` |
| `/v1/audio/transcriptions`, `/v1/audio/translations` | **Refused** today. Support is tracked in [#40](https://github.com/philterd/philter-ai-proxy/issues/40) | `400` `invalid_request` / `unsupported_content_type` |
| A body that is not a JSON object | Refused | `400` `invalid_request` / `bad_json` |

Route refused calls directly to the provider.

**Why image edits are not planned.** Redacting the `prompt` form field would mean parsing a multipart body, rewriting one field, and re-encoding the rest, which the proxy deliberately does not do.

**Why file uploads are not planned.** A batch file is many embedded requests, so redacting one upload would mean redacting every record inside a single synchronous request. Redact the file contents before uploading.

**Why audio can be supported.** Audio needs no multipart parsing: the body is binary with no inbound text to redact, so it can be forwarded untouched and the transcript scanned on the way back.

## Response Scanning (Outbound)

By default, provider responses are returned unchanged. When a route turns on outbound scanning ([Configuration](configuration.md#routes)), the proxy scans the response with the route's policy before returning it.

| Provider | Response fields scanned |
|----------|------------------------|
| OpenAI family, chat | Each choice's message content (a string or text parts), `refusal`, and tool-call and function-call arguments |
| OpenAI family, Responses | Each output item: message text and refusals, function-call arguments, and reasoning summaries |
| OpenAI family, legacy completions | Each choice's `text` |
| OpenAI family, image generation | Each image's `revised_prompt` |
| Anthropic | `text` blocks, `tool_use` input, and `thinking` text |
| Gemini, Vertex AI | Each candidate's text parts (including thought summaries) and function-call arguments |
| Ollama | `response` and `thinking`, or the message's `content`, `thinking`, and tool-call arguments |
| Bedrock | `output.message.content`: text, `toolUse.input`, and reasoning text |

Redacting an Anthropic thinking block invalidates its signature, so a client that sends the redacted block back in a later request is refused by Anthropic. Bedrock reasoning blocks behave the same way.

Responses from other OpenAI endpoints, such as embeddings and moderations, carry no generated text and are returned unchanged. Audio, image, and video bodies are returned unchanged.

### Actions

| Action | Normal response | Streamed response |
|--------|----------------|-------------------|
| `redact` (default) | Values found are replaced, and the response returned | Values found are replaced as the text is released |
| `block` | `403` `pii_blocked` / `outbound_blocked` instead of the response | The stream ends with an error event before the text containing the value is sent |
| `flag` | Returned unchanged; the values found are counted in the audit log and logged as a warning | Released unchanged; the values found are counted in the audit log |

Under `redact` and `block`, `logprobs` are removed from the response (set to `null`, or an empty array in the Responses API): their tokens spell out the original text, and they cannot be redacted to match.

A response that cannot be scanned is refused rather than returned unscanned: one that arrives compressed (the proxy asks for an uncompressed response), one that is not JSON, and a stream from an endpoint the proxy cannot scan (for example `/v1/batches`) get `502` `provider_error` / `response_unscannable`. A provider's error responses (status 400 and above) are returned unchanged and unscanned.

### Streamed responses

The proxy scans a stream as it arrives instead of forwarding each fragment at once:

- Text is held back. Once twice the holdback has accumulated (`proxy.streaming.holdback-characters`, default 256), the held text is scanned and all but the last holdback characters are released, cut at whitespace and never inside a detected value. A value split across fragments is scanned whole as long as it is shorter than the holdback.
- What is left is released when its part of the response finishes (a choice, a content block, a candidate) and when the stream ends.
- Tool-call arguments are held whole until their part finishes, then scanned and sent in one fragment. The fragment that opens a tool call (its ID and name) is sent at once.
- Keep-alive comments and pings are forwarded at once.
- Released text is sent in events shaped like the provider's own. In the Responses API, a released delta repeats the `sequence_number` of the delta it was copied from.
- Under `block`, the stream has already started with `200`, so a detection ends it with an error event in the stream's own format, such as `data: {"error": {"type": "pii_blocked", "code": "outbound_blocked", ...}}`. A stream holding data that is not a valid event is ended the same way, with `response_unscannable`, except under `flag`.

Holding text back delays each fragment by up to two holdbacks of text. A smaller holdback releases text sooner and catches only shorter values split across fragments.

## Errors

The proxy's own errors on provider traffic use the shape OpenAI-compatible clients parse. `type` and `code` are stable; `message` may change.

```json
{"error": {"message": "missing API key", "type": "unauthorized", "code": "missing_api_key", "request_id": "6f1c..."}}
```

Every response carries an `X-Request-Id` header, which the audit log records. An inbound `X-Request-Id` of at most 128 printable ASCII characters is kept; any other is replaced with a new ID.

| Status | `type` | `code` | Meaning |
|---|---|---|---|
| 400 | `invalid_request` | `path_not_canonical` | The path is not in canonical form (`..`, empty segments, encoded dots or slashes) |
| 400 | `invalid_request` | `unsupported_content_type` | The body is `multipart/form-data` |
| 400 | `invalid_request` | `bad_json` | The body is not a JSON object |
| 401 | `unauthorized` | `missing_api_key`, `invalid_api_key` | No proxy key, or an unknown one |
| 403 | `forbidden` | `scope_denied_role` | The key lacks the `proxy` role |
| 403 | `forbidden` | `scope_denied_provider`, `scope_denied_model`, `scope_denied_path` | The request is outside the key's scopes |
| 403 | `pii_blocked` | `outbound_blocked` | Response scanning under `block` found a value |
| 404 | `not_found` | `azure_disabled`, `vertex_disabled`, `bedrock_disabled`, ... | The path's provider is not configured |
| 413 | `payload_too_large` | `request_body_too_large` | The body is larger than `proxy.limits.max-request-body-bytes` |
| 500 | `configuration_error` | `policy_not_found`, `policy_invalid` | The route's policy does not exist, or cannot be used (for example, it names a model that is not installed) |
| 500 | `redaction_error` | `redaction_failed` | Redaction failed; the request was not forwarded |
| 502 | `provider_error` | `unreachable` | The provider could not be reached |
| 502 | `provider_error` | `<provider>_auth_failed` | The proxy could not get its own credentials for Bedrock, Vertex AI, or Azure (Entra ID) |
| 502 | `provider_error` | `response_unscannable` | Response scanning could not read the response |
| 503 | `capacity` | `concurrency_exceeded` | `proxy.limits.max-concurrent-requests` was reached; retry after `Retry-After` |

When redaction fails, the request is not forwarded.

## Admin API

The admin API manages policies and API keys. Every call needs a key with the `admin` role as `Authorization: Bearer <key>`; the bootstrap key has it. Errors use the shape of Philter's API:

```json
{"message": "The policy changed since it was read. Read it again and retry.", "reason": "policy_changed"}
```

`reason` is stable; `field` names the invalid parameter or field when there is one. Reasons: `invalid_request` (400), `invalid_credentials` (401), `missing_scope` (403, the key lacks the `admin` role), `not_found` (404), `policy_exists`, `policy_changed`, `policy_default`, and `self_action_refused` (409), and `internal_error` (500). Every response carries an `X-Request-Id` header, recorded with the audit events the call causes.

### Policies

The policy endpoints have the paths and bodies of [Philter's policy API](https://philterd.github.io/philter/api_and_sdks/api/policies_api/), under `/admin`. A client that takes a Philter base URL, such as `philter-sdk-java`, can use `https://<proxy>/admin`. Bodies are native Phileas policy JSON; see [Policies](policies.md).

| Method and path | Does |
|---|---|
| `GET /admin/api/policies?offset=0&limit=25` | Lists policies by name: `{"policies": [{"name", "revision", "description", "createdAt", "updatedAt"}], "total"}`. `limit` is 1 to 500. |
| `POST /admin/api/policies?name=<name>` | Creates a policy. `201`, with an `ETag`. `409` `policy_exists` when the name is taken. |
| `GET /admin/api/policies/<name>` | The policy JSON, with an `ETag`. |
| `PUT /admin/api/policies/<name>` | Replaces the policy and increments its revision. With `If-Match: <ETag>`, the write happens only if the policy has not changed since that read, else `409` `policy_changed`. |
| `DELETE /admin/api/policies/<name>` | Deletes the policy. `204`. The `default` policy cannot be deleted (`409` `policy_default`). |

A policy is checked when it is saved and again before it is used, and refused with `400` and the reason when it is not valid or names something the deployment does not allow. A name cannot contain `/`, `\`, `;`, `%`, or control characters, cannot be `.` or `..`, and is at most 256 characters.

### API keys

| Method and path | Does |
|---|---|
| `POST /admin/api/keys` | Creates a key. `201`, with the key in `key`, shown only this once. |
| `GET /admin/api/keys` | Lists keys, without their secrets: `{"keys": [...], "total"}`. |
| `DELETE /admin/api/keys/<id>` | Deletes a key. `204`. A key cannot delete itself (`409` `self_action_refused`). |

The create body:

```json
{
  "name": "support-bot",
  "roles": ["proxy"],
  "providers": ["openai", "anthropic"],
  "models": ["gpt-4o*", "claude-*"],
  "paths": ["/v1/chat/completions", "/v1/messages"],
  "policy": "support"
}
```

| Field | Meaning |
|---|---|
| `name` | A label for the key, at most 256 characters. Required. |
| `roles` | `admin` (the admin API), `proxy` (provider traffic), or both. Required. |
| `providers` | Providers the key may reach. Empty: any. An entry ending in `*` matches by prefix. |
| `models` | Models the key may request. Empty: any. An entry ending in `*` matches by prefix. A request that names no model is refused when this is set. |
| `paths` | Path prefixes the key may use. Empty: any. |
| `policy` | A policy applied to every request with this key, whatever the route says. It must exist. |

Keys are 32 random bytes, prefixed `pap_` so secret scanners can recognize them, and stored as SHA-256 hashes. A deleted key stops working on the instance at once.

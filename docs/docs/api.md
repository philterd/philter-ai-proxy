# API Reference

The proxy serves two APIs on port 8080: provider traffic, which it redacts and forwards, and the admin API under `/admin`, for policies and API keys. See [Usage](usage.md) for which path goes to which provider.

## Redacted Fields

The proxy redacts the text-bearing fields of each request before forwarding it. Every other field, such as model names, sampling parameters, tool definitions, and IDs, is forwarded unchanged.

| Provider | Request | Fields redacted |
|---|---|---|
| OpenAI family | Chat completions | Each message's `content` (a string, or the `text` or `refusal` of each content part), `refusal`, `reasoning_content` and `reasoning` (OpenAI-compatible servers), `tool_calls[].function.arguments`, and `function_call.arguments`; `prediction.content` |
| OpenAI family | Responses (`/responses`) | `instructions`; `prompt.variables` (strings and `input_text` values); `input` as a string, or each item: message content (a string or `input_text` and `output_text` parts), `function_call.arguments`, `function_call_output.output` (a string or `input_text` parts), custom tool call `input` and output, `mcp_call` arguments, output, and error, shell call output (including `stdout` and `stderr`), and reasoning summaries and text |
| OpenAI family | Embeddings, moderations, speech (`/audio/speech`) | `input` (a string or an array of strings; token-ID arrays are left alone) |
| OpenAI family | Image generation, legacy completions | `prompt` (a string or an array of strings); `suffix` (legacy completions) |
| Anthropic | Messages (`/v1/messages`, `/v1/messages/count_tokens`), and each request's `params` in a message batch (`/v1/messages/batches`) | `system` (a string or text blocks); each message's content (a string, or `text` blocks, `tool_use` input, `search_result` titles and text, and `tool_result` content as a string, text blocks, or search results) |
| Gemini, Vertex AI | `generateContent`, `streamGenerateContent`, `countTokens` | Each part's `text`, `functionCall.args`, `functionResponse.response`, `executableCode.code`, and `codeExecutionResult.output`, in `contents` and `systemInstruction`; for `countTokens`, also in a wrapped `generateContentRequest`, and every string in Vertex AI's `instances` |
| Gemini | `embedContent`, `batchEmbedContents` | The parts of `content`, as above, and `title`, in the request or in each of `requests` |
| Ollama | `/api/generate` | `prompt`, `system`, `suffix`, `template` |
| Ollama | `/api/chat` | Each message's `content`, `thinking`, and `tool_calls[].function.arguments` |
| Ollama | `/api/embed`, `/api/embeddings` | `input` (a string or an array of strings); `prompt` (`/api/embeddings`) |
| Ollama | `/api/show` | Nothing: the request names a model, and neither it nor the response carries conversation text. Forwarded unchanged |
| Bedrock | Converse | `system[].text` and `guardContent` text; each message's `text` blocks, `guardContent` text, `toolUse.input`, and `toolResult.content` (text and JSON) |
| Bedrock | InvokeModel, Anthropic Claude models | The Messages API fields listed for Anthropic above, and `prompt` for legacy Text Completions models (Claude 2, Instant). With response scanning on, a legacy model's stream cannot be scanned and is ended with `response_unscannable` |
| Bedrock | InvokeModel, Amazon Titan embedding models | `inputText` |
| Bedrock | InvokeModel, Cohere Embed models | `texts`, and the `text` parts of `inputs` |

The OpenAI family is OpenAI, Azure OpenAI, and the OpenAI-compatible providers. Arguments and other JSON held in a string are parsed, each string in them redacted, and the JSON written back; when they are not JSON, the whole string is redacted as text.

Not redacted: Anthropic thinking blocks and Bedrock reasoning blocks sent back in a conversation. The providers verify their signatures, so a redacted block would make the request fail. Their text reaches the provider as the client sends it. If thinking can hold sensitive values, have the client drop thinking blocks from the conversation history it sends back.

**Embeddings are computed from the redacted text.** Search by meaning still works on such embeddings, but a search for a redacted value matches any text where that kind of value was redacted, not that value. When documents and queries are redacted with the same policy and context, and the policy's strategy replaces a value the same way each time, an exact value can still be matched through its replacement. The client's own copy of the text is not changed.

All the fields of one request are redacted together, against one policy. Without a configured context, a value is replaced the same way in every field of the request and in its response, when the policy's strategy uses `"replacementScope": "CONTEXT"`. See [Contexts](policies.md#contexts).

### Images, audio, and files are not redacted

Only text is redacted. The proxy does not inspect images, audio, video, or files embedded in a JSON request, including any text, faces, or spoken words they contain. By default it refuses a request that carries one with `400 invalid_request` / `media_not_allowed`, and the error message names the part it found. Set `media: forward` in `proxy.defaults` or on a route to forward such requests instead, with the media unchanged. See [Routes](configuration.md#routes).

| Provider | Parts refused, or forwarded unredacted under `media: forward` |
|----------|--------------|
| OpenAI / OpenAI-compatible / Azure OpenAI | Chat completions: every content part other than `text`, `input_text`, `output_text`, and `refusal`, such as `image_url`, `input_audio`, `file`, or an OpenAI-compatible server's `video_url`. Responses API: `input_image`, `input_file`, `input_audio`, and `computer_screenshot`, in messages, tool outputs, and `prompt.variables`. Moderations: image inputs |
| Anthropic | `image`, `document`, and `container_upload` content blocks, including those in tool results and message batches |
| Gemini / Vertex AI | `inlineData` and `fileData` parts, including those in function responses, a wrapped `generateContentRequest`, and embedding requests |
| Bedrock Converse | `image`, `document`, and `video` content blocks, including those in tool results, and images in `guardContent` (system or message) |
| Bedrock InvokeModel | Claude: as for Anthropic. Titan: `inputImage`. Cohere Embed: a non-empty `images` list, and `inputs` parts other than `text` |
| Ollama | A non-empty `images` list |

The same holds for responses: response scanning reads response text only, so generated images and audio, and the transcript that accompanies audio output, are returned unscanned. `media` applies to requests only.

If images, audio, or files sent to a provider can contain sensitive data, remove or redact them before the request reaches the proxy, or route those requests elsewhere. Multipart uploads (files, audio transcription, image edits) are refused under either setting; see [Supported request types](#supported-request-types).

## Supported request types

The proxy accepts a JSON request body. **It does not parse `multipart/form-data`.** It decodes the request path once (so `/v1/chat/completion%73` is handled as `/v1/chat/completions`) and forwards the path as the client encoded it.

| Request type | Behavior | Error |
|---|---|---|
| The requests in the table above | Redacted, then forwarded | - |
| A request without a body, such as `GET /v1/models` | Forwarded unchanged when response scanning is off for its route. With scanning on, refused unless the endpoint is in the table above, since its response cannot be scanned. To a provider the proxy authenticates to with its own credential (Vertex AI, Bedrock, and Azure OpenAI with Entra ID), refused unless the endpoint is in the table above, since the proxy would otherwise act for any key on any endpoint, such as deleting resources | `400` `invalid_request` / `unsupported_endpoint` |
| Any other request with a JSON body, such as `/v1/batches`, `/v1/threads/{id}/messages`, Anthropic `/v1/messages/batches/{id}/cancel`, or Vertex AI `:predict` | **Refused** by default: the proxy does not know where the text is, so it cannot redact it. Set `unsupported-endpoints: forward` on a route to forward it unredacted, with its response unscanned | `400` `invalid_request` / `unsupported_endpoint` |
| `/v1/images/edits`, `/v1/images/variations` | **Refused.** Not supported, and not planned | `400` `invalid_request` / `unsupported_content_type` |
| `/v1/files` (uploads) | **Refused.** Not supported, and not planned | `400` `invalid_request` / `unsupported_content_type` |
| `/v1/audio/transcriptions`, `/v1/audio/translations` | **Refused** today. Support is tracked in [#40](https://github.com/philterd/philter-ai-proxy/issues/40) | `400` `invalid_request` / `unsupported_content_type` |
| A JSON request carrying images, audio, video, or files | Refused, unless `media` is `forward` for the route | `400` `invalid_request` / `media_not_allowed` |
| A body that is not a JSON object | Refused | `400` `invalid_request` / `bad_json` |

Route refused calls directly to the provider.

**Why image edits are not planned.** Redacting the `prompt` form field would mean parsing a multipart body, rewriting one field, and re-encoding the rest, which the proxy deliberately does not do.

**Why file uploads are not planned.** A batch file is many embedded requests, so redacting one upload would mean redacting every record inside a single synchronous request. Redact the file contents before uploading.

**Why audio can be supported.** Audio needs no multipart parsing: the body is binary with no inbound text to redact, so it can be forwarded untouched and the transcript scanned on the way back.

### Endpoints by provider

A request with a body to an endpoint not listed as redacted is refused with `unsupported_endpoint` unless `unsupported-endpoints` is `forward`. Uploads (`multipart/form-data`) are refused with `unsupported_content_type` under either setting. The refused column names common examples, not every endpoint. A request without a body, such as listing models, retrieving a batch's results, or cancelling a batch or response, is forwarded unchanged when response scanning is off, except to the providers the proxy authenticates to itself (Vertex AI, Bedrock, and Azure OpenAI with Entra ID), where it is refused.

| Provider | Redacted | Refused (examples) |
|---|---|---|
| OpenAI, Azure OpenAI, OpenAI-compatible | Chat completions, Responses, legacy completions, embeddings, moderations, image generation, speech | Creating batches, file uploads, Assistants and threads, vector stores, fine-tuning, updating a stored chat completion, audio transcription and translation, image edits and variations. The Realtime API (WebSocket) is not proxied |
| Anthropic | Messages, token counting, creating a message batch | Files API uploads |
| Gemini, Vertex AI | `:generateContent`, `:streamGenerateContent`, `:countTokens`; on Gemini, also `:embedContent` and `:batchEmbedContents` | Vertex AI embeddings (`:predict`, `:embedContent`) and other `:predict` calls, cached contents, file uploads. The Live API (WebSocket) is not proxied |
| Amazon Bedrock | Converse and ConverseStream for any model. InvokeModel for Anthropic Claude, Amazon Titan embedding, and Cohere Embed models, and InvokeModelWithResponseStream for Claude, by model ID or cross-region inference profile ID (such as `us.anthropic.claude-...`) | InvokeModel for other model families, such as Meta Llama, Mistral, and Amazon Nova; ApplyGuardrail; asynchronous invocation. A model given as an ARN is refused with `400` under either setting, since its `/` is sent encoded as `%2F`, which is not accepted in a path |
| Ollama | `/api/generate`, `/api/chat`, `/api/embed`, `/api/embeddings`; `/api/show` is forwarded unchanged | `/api/create`, `/api/copy`, `/api/pull`, `/api/push`, `/api/delete`. Pull and delete can be forwarded with routes; see [Model management](usage.md#model-management) |

## Response Scanning (Outbound)

By default, provider responses are returned unchanged. When a route turns on outbound scanning ([Configuration](configuration.md#routes)), the proxy scans the response with the route's policy before returning it.

| Provider | Response fields scanned |
|----------|------------------------|
| OpenAI family, chat | Each choice's message content (a string or text parts), `refusal`, `reasoning_content` and `reasoning`, and tool-call and function-call arguments |
| OpenAI family, Responses | Each output item, read as the request's `input` items are: message text and refusals, function and custom tool call arguments and input, tool and MCP call output, and reasoning summaries and text |
| OpenAI family, legacy completions | Each choice's `text` |
| OpenAI family, image generation | Each image's `revised_prompt` |
| Anthropic | `text` blocks and their citations (the quoted `cited_text` and the source's title), `tool_use` and `server_tool_use` input, and `thinking` text |
| Gemini, Vertex AI | Each candidate's text parts (including thought summaries), function-call arguments, and executable code and its output; and its grounding metadata: the answer passages citations quote, the search and retrieval queries, the rendered search suggestions, and the titles and text of grounding sources (including documents retrieved from Vertex AI Search). Citation offsets into the answer are not adjusted, so once the answer is redacted they are approximate |
| Ollama | `response` and `thinking`, or the message's `content`, `thinking`, and tool-call arguments |
| Bedrock, Converse | `output.message.content`: text, `toolUse.input`, and reasoning text |
| Bedrock, InvokeModel (Claude) | As for Anthropic, and a legacy model's `completion` |

Redacting an Anthropic thinking block invalidates its signature, so a client that sends the redacted block back in a later request is refused by Anthropic. Bedrock reasoning blocks behave the same way.

Responses from other OpenAI endpoints, such as embeddings and moderations, from Ollama's embeddings and `/api/show`, from Gemini and Vertex AI `countTokens` and Gemini embeddings, and from Bedrock's Titan and Cohere embedding models, carry no generated text and are returned unchanged. Audio, image, and video bodies are returned unchanged.

### Actions

| Action | Normal response | Streamed response |
|--------|----------------|-------------------|
| `redact` (default) | Values found are replaced, and the response returned | Values found are replaced as the text is released |
| `block` | `403` `pii_blocked` / `outbound_blocked` instead of the response | The stream ends with an error event before the text containing the value is sent |
| `flag` | Returned unchanged; the values found are counted in the audit log and logged as a warning | Released unchanged; the values found are counted in the audit log |

Under `redact` and `block`, data that spells out the original text and cannot be redacted to match is removed: OpenAI `logprobs` (set to `null`, or an empty array in the Responses API), Gemini `logprobsResult`, Ollama `logprobs` and `context` (the conversation's token IDs), and Bedrock guardrail traces (`trace` in Converse, `amazon-bedrock-trace` in InvokeModel), which can quote the text a guardrail matched.

In JSON such as tool-call arguments, strings are redacted, and so are integers of five or more digits, since an SSN, phone number, or account number can be sent as a number. A number the policy changes is replaced by its redacted text, as a string. Shorter integers, decimals, and object keys are not redacted.

A response that cannot be scanned is refused rather than returned unscanned: one that arrives compressed (the proxy asks for an uncompressed response), one that is not JSON, a stream from an endpoint the proxy cannot scan (for example embeddings), a binary response (`audio/`, `image/`, `video/`, `application/octet-stream`) from any endpoint but speech, a redirect or other 1xx or 3xx status, a stream event whose name is not a plain identifier, and a Bedrock stream that carries an exception message get `502` `provider_error` / `response_unscannable`. A response larger than `proxy.limits.max-response-body-bytes`, or a stream with a line, event, or held text over 16 Mi characters, gets `response_too_large`. A provider's error responses (status 400 and above) are returned unchanged and unscanned. In a scanned stream, an event without data (a keep-alive comment, or only `id:` or `retry:` lines) is forwarded as a bare `:` comment, and `id:` and `retry:` lines are dropped from events with data, since their text is not scanned. A stream the provider cuts short is ended with an error event and recorded in the audit log as `stream_interrupted`.

### Streamed responses

The proxy scans a stream as it arrives instead of forwarding each fragment at once:

- Text is held back. Once twice the holdback has accumulated (`proxy.streaming.holdback-characters`, default 256), the held text is scanned and all but the last holdback characters are released, cut at whitespace and never inside a detected value. A value split across fragments is scanned whole as long as it is shorter than the holdback.
- What is left is released when its part of the response finishes (a choice, a content block, a candidate) and when the stream ends.
- Tool-call arguments are held whole until their part finishes, then scanned and sent in one fragment. The fragment that opens a tool call (its ID and name) is sent at once.
- Keep-alive comments and pings are forwarded at once.
- Released text is sent in events shaped like the provider's own. In the Responses API, a released delta repeats the `sequence_number` of the delta it was copied from.
- Under `block`, the stream has already started with `200`, so a detection ends it with an error event in the stream's own format, such as `data: {"error": {"type": "pii_blocked", "code": "outbound_blocked", ...}}`. A Bedrock stream is ended with an AWS event stream error message (`:message-type error`, with the code in `:error-code`), which AWS SDKs raise. A stream holding data that is not a valid event is ended the same way, with `response_unscannable`, except under `flag`. A stream is also ended this way with `response_too_large`, or with `redaction_failed` when scanning fails.

Holding text back delays each fragment by up to two holdbacks of text. A smaller holdback releases text sooner and catches only shorter values split across fragments.

## Errors

The proxy's own errors on provider traffic use the shape OpenAI-compatible clients parse. `type` and `code` are stable; `message` may change.

```json
{"error": {"message": "missing API key", "type": "unauthorized", "code": "missing_api_key", "request_id": "6f1c..."}}
```

Every response carries an `X-Request-Id` header, which the audit log records. An inbound `X-Request-Id` of at most 128 printable ASCII characters is kept; any other is replaced with a new ID.

| Status | `type` | `code` | Meaning |
|---|---|---|---|
| 400 | `invalid_request` | `path_not_canonical` | The path is not in canonical form once decoded (`..`, empty segments), or has an escape that decodes to invalid UTF-8, a control character, or one of `%`, `?`, `#`. A malformed escape or an encoded `/` or `\` (`%2F`, `%5C`) is refused with a plain `400` from the web server, without this body |
| 400 | `invalid_request` | `ambiguous_field` | An OpenAI-family or Ollama request names a field the proxy reads (such as a redacted field, `model`, or `name`) in another case, such as `Messages` or `Model`, or with `ſ` or `K` (Kelvin sign), which Go's `encoding/json` folds to `s` and `k`. A server that ignores case would read it in place of the field the proxy checked. Keys inside tool definitions, schemas, `metadata`, and tool arguments are not checked |
| 400 | `invalid_request` | `unsupported_endpoint` | The endpoint is not one the proxy can redact, or, with response scanning on, scan; and `unsupported-endpoints` is `reject`. See [Supported request types](#supported-request-types) |
| 400 | `invalid_request` | `unsupported_content_type` | The body is `multipart/form-data` |
| 400 | `invalid_request` | `bad_json` | The body is not a JSON object |
| 400 | `invalid_request` | `media_not_allowed` | The request carries an image, audio, video, or file part and `media` is `reject`. See [Images, audio, and files are not redacted](#images-audio-and-files-are-not-redacted) |
| 401 | `unauthorized` | `missing_api_key`, `invalid_api_key` | No proxy key, or an unknown one |
| 403 | `forbidden` | `scope_denied_role` | The key lacks the `proxy` role |
| 403 | `forbidden` | `scope_denied_provider`, `scope_denied_model`, `scope_denied_path` | The request is outside the key's scopes |
| 403 | `pii_blocked` | `outbound_blocked` | Response scanning under `block` found a value |
| 404 | `not_found` | `azure_disabled`, `vertex_disabled`, `bedrock_disabled`, ... | The path's provider is not configured |
| 403 | `forbidden` | `vertex_project_denied` | A Vertex AI path (`/v1/projects/...` or `/v1beta1/projects/...`) names a project or location other than the configured one |
| 413 | `payload_too_large` | `request_body_too_large` | The body is larger than `proxy.limits.max-request-body-bytes` |
| 502 | `provider_error` | `response_too_large` | Response scanning is on and the response is larger than the proxy will scan. See [Response Scanning](#response-scanning-outbound) |
| 500 | `configuration_error` | `policy_not_found`, `policy_invalid` | The route's policy does not exist, or cannot be used (for example, it names a model that is not installed) |
| 500 | `redaction_error` | `redaction_failed` | Redaction failed; the request was not forwarded |
| 500 | `internal_error` | `internal_error` | An unexpected failure in the proxy; the log has the details under the request ID |
| 502 | `provider_error` | `unreachable` | The provider could not be reached |
| 502 | `provider_error` | `<provider>_auth_failed` | The proxy could not get its own credentials for Bedrock, Vertex AI, or Azure (Entra ID) |
| 502 | `provider_error` | `response_unscannable` | Response scanning could not read the response |
| 503 | `redaction_error` | `redaction_timeout` | Redaction took longer than `proxy.limits.redaction-timeout-ms` |
| 503 | `capacity` | `concurrency_exceeded` | `proxy.limits.max-concurrent-requests` was reached; retry after `Retry-After` |

When redaction fails, the request is not forwarded.

For requests routed to Bedrock, the error code is also sent in the `x-amzn-ErrorType` header, and the body carries a top-level `message` (`"<code>: <message>"`), so AWS SDKs report them.

## Admin API

The admin API manages policies and API keys. Every call needs a key with the `admin` role as `Authorization: Bearer <key>`; the bootstrap key has it. Errors use the shape of Philter's API:

```json
{"message": "The policy changed since it was read. Read it again and retry.", "reason": "policy_changed"}
```

`reason` is stable; `field` names the invalid parameter, field, or header (`If-Match`) when there is one. Reasons: `invalid_request` (400), `invalid_credentials` (401), `missing_scope` (403, the key lacks the `admin` role), `not_found` (404), `policy_exists`, `policy_changed`, `policy_default`, and `self_action_refused` (409), and `internal_error` (500). Every response carries an `X-Request-Id` header, recorded with the audit events the call causes.

A request with a body needs `Content-Type: application/json`. A request under `/admin`, or to `/livez`, `/readyz`, or `/health`, that no endpoint accepts (an unknown path, or the wrong method or content type) is answered `404` `not_found` and never forwarded to a provider.

### Policies

The policy endpoints have the paths and bodies of [Philter's policy API](https://philterd.github.io/philter/api_and_sdks/api/policies_api/), under `/admin`. A client that takes a Philter base URL, such as `philter-sdk-java`, can use `https://<proxy>/admin`. Bodies are native Phileas policy JSON; see [Policies](policies.md).

| Method and path | Does |
|---|---|
| `GET /admin/api/policies?offset=0&limit=25` | Lists policies by name: `{"policies": [{"name", "revision", "description", "createdAt", "updatedAt"}], "total"}`. `limit` is 1 to 500. |
| `POST /admin/api/policies?name=<name>` | Creates a policy. `201`, with an `ETag`. `409` `policy_exists` when the name is taken. |
| `GET /admin/api/policies/<name>` | The policy JSON, with an `ETag`. |
| `PUT /admin/api/policies/<name>` | Replaces the policy and increments its revision. `200`, with the new `ETag`; `404` when the policy does not exist. With `If-Match: <ETag>`, the write happens only if the policy has not changed since that read, else `409` `policy_changed`. Without `If-Match`, or with `*`, the write is unconditional. |
| `DELETE /admin/api/policies/<name>` | Deletes the policy. `204`. The `default` policy cannot be deleted (`409` `policy_default`). |

A policy is checked when it is saved and again before it is used, and refused with `400` and the reason when it is not valid or names something the deployment does not allow. A name cannot contain `/`, `\`, `;`, `%`, or control characters, cannot be `.` or `..`, and is at most 256 characters.

### API keys

| Method and path | Does |
|---|---|
| `POST /admin/api/keys` | Creates a key. `201`, with the key's fields and the key itself in `key`, shown only this once. |
| `GET /admin/api/keys` | Lists keys, without their secrets: `{"keys": [{"id", "name", "createdAt", "roles", "providers", "models", "paths", "policy"}], "total"}`. `policy` is present only when one is bound. |
| `DELETE /admin/api/keys/<id>` | Deletes a key. `204`; `404` when there is no such key. A key cannot delete itself (`409` `self_action_refused`). |

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
| `models` | Models the key may request. Empty: any. An entry ending in `*` matches by prefix. A request that names no model is refused when this is set, and so is one whose body names models other than its own: an Anthropic message batch whose requests name different models, or a Gemini `countTokens` or `batchEmbedContents` request naming a model other than the one in its path. |
| `paths` | Paths the key may use. Each covers itself and the paths below it, on a segment boundary: `/v1/messages` allows `/v1/messages/count_tokens` but not `/v1/messagesx`, and a Gemini model path allows its methods (`...:generateContent`). Paths are matched after decoding, against the path as sent, so an OpenAI-compatible provider's paths include its prefix (`/vllm/v1/chat/completions`). Empty: any. |
| `policy` | A policy applied to every request with this key, whatever the route says. It must exist. |

Keys are 32 random bytes, prefixed `pap_` so secret scanners can recognize them, and stored as SHA-256 hashes. A deleted key stops working on the instance at once.

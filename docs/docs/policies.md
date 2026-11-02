# Policies

A policy says what to find and what to replace it with. Policies are native [Phileas policies](https://philterd.github.io/phileas/filter_policies/filter_policies/), the same JSON Philter uses, so a policy written for one works in the other within the restrictions in [What a policy may not do](#what-a-policy-may-not-do). See [Filters](https://philterd.github.io/phileas/filter_policies/filters/) and [Filter Strategies](https://philterd.github.io/phileas/filter_policies/filter_strategies/) in the Phileas documentation for everything a policy can contain.

Policies are stored in the proxy's database, encrypted with the encryption key, and managed with the [admin API](api.md#policies).

## The default policy

The proxy creates a policy named `default` on first start. It can be replaced but not deleted.

```json
{
  "identifiers": {
    "person": {
      "phEyeConfiguration": {
        "modelPath": "ph-eye-pii-en-small",
        "labels": ["name"],
        "threshold": 0.9
      },
      "phEyeFilterStrategies": [
        { "strategy": "REDACT" }
      ]
    },
    "ssn": {
      "ssnFilterStrategies": [
        { "strategy": "REDACT" }
      ]
    },
    "emailAddress": {
      "emailAddressFilterStrategies": [
        { "strategy": "REDACT" }
      ]
    }
  }
}
```

It finds person names with the `ph-eye-pii-en-small` model the Docker image includes, Social Security numbers, and email addresses, and replaces each with a token such as `{{{REDACTED-ssn}}}`.

## Managing policies

Create a policy:

```bash
curl -k "https://localhost:8080/admin/api/policies?name=support" \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "identifiers": {
      "phoneNumber": { "phoneNumberFilterStrategies": [ { "strategy": "MASK" } ] },
      "creditCard": { "creditCardFilterStrategies": [ { "strategy": "REDACT" } ] }
    }
  }'
```

Read it, change it, and write it back only if nobody changed it in between:

```bash
curl -k -i https://localhost:8080/admin/api/policies/support -H "Authorization: Bearer $ADMIN_KEY"
# ETag: "0-..."

curl -k -X PUT https://localhost:8080/admin/api/policies/support \
  -H "Authorization: Bearer $ADMIN_KEY" \
  -H "Content-Type: application/json" \
  -H 'If-Match: "0-..."' \
  -d @support-policy.json
```

A change applies to the next request. The [Policy Editor](https://policies.philterd.ai) builds policies without writing JSON.

## Choosing the policy for a request

1. A key created with a `policy` uses that policy for every request, whatever the route says. See [API keys](api.md#api-keys).
2. Otherwise, the first route that matches the request decides. See [Routes](configuration.md#routes).
3. Otherwise, `proxy.defaults.policy` applies: `default` unless configured.

The response is scanned with the same policy as the request.

A request whose policy does not exist, or cannot be used, is refused with `500` `policy_not_found` or `policy_invalid`, and not forwarded. A request without a body whose response is not scanned, such as `GET /v1/models`, does not use the policy and is forwarded. The proxy loads the default and route policies when it starts and logs any it cannot use.

## Models

A PhEye filter finds entities with a GLiNER model that runs inside the proxy. `modelPath` names a model in the models directory (`proxy.models.directory`, `/opt/philter-ai-proxy/models` in the image): each subdirectory holding `gliner_config.json`, `tokenizer.json`, and `model.onnx` (or `onnx/model.onnx`) is a model named after the directory. The image includes `ph-eye-pii-en-small`.

To use another model, mount a directory of models over the models directory, or set `proxy.models.directory`, and name the model in the policy. The directory is read when a policy is saved or loaded, so a model added there can be used without a restart.

## What a policy may not do

Whoever writes a policy must not be able to send the text being redacted somewhere else, so the proxy refuses a policy that:

- names a PhEye `endpoint` or `bearerToken`. The proxy runs models in-process and calls no PhEye service, so every PhEye filter needs a `modelPath` naming a model in the models directory.
- defines `generators`, which call an external service.
- names a file (such as a dictionary file) outside the directories in `proxy.policy-files.directories`. With none configured, the default, a policy may name no file.
- names an environment variable (`env:NAME`) not listed in `proxy.policy-files.allowed-environment-variables`. With none listed, the default, a policy may name none.

These rules are stricter than Philter's, which can call a PhEye service. A policy is checked when it is saved and again before it is used, and refused with the reason.

## Contexts

A context keeps the replacement chosen for each value, so the same value is replaced the same way every time. That matters for strategies that choose a replacement, such as `RANDOM_REPLACE`: with a context, a name replaced by a fake name stays the same fake name across a conversation.

- **Within one request and its response**, the proxy always uses a context of its own, so a value is replaced the same way in every message of the request, in the response, and throughout a streamed response.
- **Across requests**, set `context` on a route or in `proxy.defaults` to a name of your choosing. Its replacements are stored in the proxy's database, encrypted with the encryption key, and found by a keyed hash of each original value; the originals themselves are not stored.

Either way, a strategy reuses replacements only when it sets `"replacementScope": "CONTEXT"`:

```json
{
  "identifiers": {
    "ssn": {
      "ssnFilterStrategies": [
        { "strategy": "RANDOM_REPLACE", "replacementScope": "CONTEXT" }
      ]
    }
  }
}
```

`REDACT` replaces every value of a type with the same token, so it needs no context.

## Reversible strategies

`CRYPTO_REPLACE` and `FPE_ENCRYPT_REPLACE` encrypt a value instead of removing it, with a key the policy supplies (or names as an allowed environment variable). The proxy does not restore encrypted values in responses, and does not yet offer a re-identification endpoint; that is tracked in [#21](https://github.com/philterd/philter-ai-proxy/issues/21).

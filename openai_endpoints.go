package main

import (
	"context"
	"encoding/json"
	"strings"
)

// openAIEndpoint classifies an OpenAI-style request by its path suffix. The
// same classification serves the OpenAI provider (`/v1/...`), Azure OpenAI
// (`/openai/deployments/{deployment}/...`), and openai-compatible providers
// (path already prefix-stripped), since all three funnel through
// handleOpenAICompatible.
type openAIEndpoint int

const (
	epChat        openAIEndpoint = iota // .../chat/completions
	epResponses                         // .../responses (OpenAI Responses API)
	epEmbeddings                        // .../embeddings
	epModerations                       // .../moderations
	epImageGen                          // .../images/generations
	epAudioSpeech                       // .../audio/speech
	epCompletions                       // .../completions (legacy, non-chat)
	epPassthrough                       // batch, files, anything else: no inline text to redact
)

// classifyOpenAIEndpoint maps a request path to an endpoint kind. Chat is
// matched before the legacy completions suffix because "/chat/completions" also
// ends with "/completions".
func classifyOpenAIEndpoint(path string) openAIEndpoint {
	p := strings.ToLower(path)
	switch {
	case strings.HasSuffix(p, "/chat/completions"):
		return epChat
	case strings.HasSuffix(p, "/responses"):
		return epResponses
	case strings.HasSuffix(p, "/embeddings"):
		return epEmbeddings
	case strings.HasSuffix(p, "/moderations"):
		return epModerations
	case strings.HasSuffix(p, "/images/generations"):
		return epImageGen
	case strings.HasSuffix(p, "/audio/speech"):
		return epAudioSpeech
	case strings.HasSuffix(p, "/completions"):
		return epCompletions
	default:
		return epPassthrough
	}
}

// redactOpenAIEndpoint applies the redaction appropriate to the endpoint kind,
// mutating `root` in place. It returns an error only when a Philter call fails
// (the caller maps that to a philterError response).
//
// All text-bearing fields are run through redactAny, which recurses through
// strings/arrays/objects and leaves non-string scalars (e.g. embeddings token
// IDs) untouched. Only the relevant field(s) per endpoint are passed in, so
// structural fields (model, dimensions, encoding_format, ...) are never sent to
// Philter.
func (p *Proxy) redactOpenAIEndpoint(ctx context.Context, ep openAIEndpoint, root map[string]json.RawMessage, philterCtx, docID, policy string, audit *AuditEntry) error {
	switch ep {
	case epChat:
		return p.redactChatMessages(ctx, root, philterCtx, docID, policy, audit)
	case epResponses:
		if err := p.redactRootField(ctx, root, "input", philterCtx, docID, policy, audit); err != nil {
			return err
		}
		return p.redactRootField(ctx, root, "instructions", philterCtx, docID, policy, audit)
	case epEmbeddings, epModerations, epAudioSpeech:
		return p.redactRootField(ctx, root, "input", philterCtx, docID, policy, audit)
	case epImageGen, epCompletions:
		return p.redactRootField(ctx, root, "prompt", philterCtx, docID, policy, audit)
	default: // epPassthrough — batch/files/unknown carry no inline prompt text
		return nil
	}
}

// redactRootField redacts a single top-level field that holds text (a string,
// an array of strings, or a nested structure). A field that is absent, empty,
// or non-textual (e.g. an array of token IDs) is left unchanged.
func (p *Proxy) redactRootField(ctx context.Context, root map[string]json.RawMessage, key, philterCtx, docID, policy string, audit *AuditEntry) error {
	raw, ok := root[key]
	if !ok || len(raw) == 0 {
		return nil
	}
	var v any
	if err := json.Unmarshal(raw, &v); err != nil {
		return nil
	}
	redacted, err := redactAny(ctx, p.philter.Filter, v, philterCtx, docID, policy, audit)
	if err != nil {
		return err
	}
	b, err := json.Marshal(redacted)
	if err != nil {
		return nil // leave the field unchanged if it somehow can't be re-marshaled
	}
	root[key] = b
	return nil
}

// redactChatMessages redacts the `messages` array of a chat-completions request
// in place: string `content` and `tool_calls[].function.arguments` on each
// message. Other top-level fields are preserved by the caller.
func (p *Proxy) redactChatMessages(ctx context.Context, root map[string]json.RawMessage, philterCtx, docID, policy string, audit *AuditEntry) error {
	rawMsgs, ok := root["messages"]
	if !ok || len(rawMsgs) == 0 {
		return nil
	}
	var messages []OpenAIMessage
	if err := json.Unmarshal(rawMsgs, &messages); err != nil {
		// Not the expected shape; leave untouched rather than corrupt the body.
		return nil
	}

	for i := range messages {
		msg := &messages[i]

		if len(msg.Content) > 0 {
			var s string
			if json.Unmarshal(msg.Content, &s) == nil && s != "" {
				fr, err := p.philter.Filter(ctx, s, philterCtx, docID, policy)
				if err != nil {
					return err
				}
				msg.Content, _ = json.Marshal(fr.FilteredText)
				audit.recordFilterResult(fr)
			}
		}

		for j := range msg.ToolCalls {
			tc := &msg.ToolCalls[j]
			if tc.Function.Arguments != "" {
				redacted, err := redactJSONArguments(ctx, p.philter.Filter, tc.Function.Arguments, philterCtx, docID, policy, audit)
				if err != nil {
					return err
				}
				tc.Function.Arguments = redacted
			}
		}
	}

	newMsgs, err := json.Marshal(messages)
	if err != nil {
		return nil
	}
	root["messages"] = newMsgs
	return nil
}

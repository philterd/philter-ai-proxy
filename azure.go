package main

import (
	"context"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore"
	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

// azureCognitiveScope is the OAuth scope for Azure OpenAI (Cognitive Services)
// when authenticating with an Azure AD / Entra ID token.
const azureCognitiveScope = "https://cognitiveservices.azure.com/.default"

// isAzurePath reports whether a request path targets Azure OpenAI, which uses
// deployment-based routing: /openai/deployments/{deployment}/{chat/completions,
// completions, embeddings}.
func isAzurePath(path string) bool {
	return strings.HasPrefix(path, "/openai/deployments/")
}

// tokenSource yields a bearer token for outbound auth. Abstracted so tests can
// inject a fake without standing up a real Azure credential.
type tokenSource interface {
	token(ctx context.Context) (string, error)
}

// azureTokenProvider acquires and caches an Entra ID access token from the
// default Azure credential chain (managed identity, workload identity,
// environment, etc.). Tokens are refreshed shortly before expiry.
type azureTokenProvider struct {
	cred  azcore.TokenCredential
	scope string

	mu     sync.Mutex
	cached azcore.AccessToken
}

func newAzureTokenProvider() (*azureTokenProvider, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, err
	}
	return &azureTokenProvider{cred: cred, scope: azureCognitiveScope}, nil
}

func (a *azureTokenProvider) token(ctx context.Context) (string, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.cached.Token != "" && time.Until(a.cached.ExpiresOn) > 5*time.Minute {
		return a.cached.Token, nil
	}
	tok, err := a.cred.GetToken(ctx, policy.TokenRequestOptions{Scopes: []string{a.scope}})
	if err != nil {
		return "", err
	}
	a.cached = tok
	return tok.Token, nil
}

// azureAuthMode returns a human-readable auth mode for log lines.
func azureAuthMode(entraID bool) string {
	if entraID {
		return "entra-id"
	}
	return "api-key"
}

// handleAzure proxies an Azure OpenAI request. Azure request/response bodies are
// OpenAI-compatible, so redaction and token-usage accounting reuse the OpenAI
// path verbatim; the Azure-specific work is (1) injecting a default api-version
// when the client omits one and (2) attaching an Entra ID bearer token when
// configured (otherwise the client's api-key header passes through unchanged).
func (p *Proxy) handleAzure(w http.ResponseWriter, r *http.Request, bodyBytes []byte, philterCtx, documentID, policyName string, audit *AuditEntry, outbound OutboundConfig) {
	// Inject a default api-version if the request lacks one and a default is set.
	if p.config.Providers.Azure.APIVersion != "" && r.URL.Query().Get("api-version") == "" {
		q := r.URL.Query()
		q.Set("api-version", p.config.Providers.Azure.APIVersion)
		r.URL.RawQuery = q.Encode()
	}

	// Entra ID auth: acquire a bearer token and set it. Forwarding copies the
	// Authorization header through to Azure (the proxy's own auth header was
	// already stripped upstream).
	if p.azureCred != nil {
		tok, err := p.azureCred.token(r.Context())
		if err != nil {
			slog.Error("Azure AD token acquisition failed", "error", err, "request_id", audit.RequestID)
			writeError(w, audit, http.StatusBadGateway, "provider_error", "azure_auth_failed", "failed to acquire Azure AD token")
			return
		}
		r.Header.Set("Authorization", "Bearer "+tok)
	}

	p.handleOpenAICompatible(w, r, bodyBytes, philterCtx, documentID, policyName, audit, outbound, p.azureTarget, p.azureClient, "azure")
}

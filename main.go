package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"

	"github.com/google/uuid"
)

type Message struct {
	Role    string `json:"role"`
	Content string `json:"content"`
}

type OpenAIRequest struct {
	Model    string    `json:"model"`
	Messages []Message `json:"messages"`
}

type AnthropicContent struct {
	Type string `json:"type"`
	Text string `json:"text,omitempty"`
}

type AnthropicMessage struct {
	Role    string `json:"role"`
	Content any    `json:"content"` // Can be string or []AnthropicContent
}

type AnthropicRequest struct {
	Model    string             `json:"model"`
	Messages []AnthropicMessage `json:"messages"`
	System   string             `json:"system,omitempty"`
}

type GeminiPart struct {
	Text string `json:"text"`
}

type GeminiContent struct {
	Role  string       `json:"role,omitempty"`
	Parts []GeminiPart `json:"parts"`
}

type GeminiRequest struct {
	Contents []GeminiContent `json:"contents"`
}

type Proxy struct {
	openaiTarget    *url.URL
	anthropicTarget *url.URL
	geminiTarget    *url.URL
	openaiProxy     *httputil.ReverseProxy
	anthropicProxy  *httputil.ReverseProxy
	geminiProxy     *httputil.ReverseProxy
}

type FilterResponse struct {
	FilteredText string `json:"filteredText"`
	Context      string `json:"context"`
	DocumentId   string `json:"documentId"`
}

func Filter(endpoint string, input string, context string, documentId string, policyName string) FilterResponse {

	var text = []byte(input)

	base, err := url.Parse(endpoint + "/api/filter")

	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	params := url.Values{}
	params.Add("c", context)
	params.Add("d", documentId)
	params.Add("p", policyName)

	base.RawQuery = params.Encode()

	http.DefaultTransport.(*http.Transport).TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	request, err := http.NewRequest("POST", base.String(), bytes.NewReader(text))

	if err != nil {
		fmt.Print(err.Error())
		os.Exit(1)
	}

	request.Header.Add("Content-Type", "text/plain")

	client := &http.Client{}
	response, err := client.Do(request)

	documentId = response.Header.Get("x-document-id")

	responseData, err := ioutil.ReadAll(response.Body)

	if err != nil {
		log.Fatal(err)
	}

	response.Body.Close()

	return FilterResponse{FilteredText: string(responseData), Context: context, DocumentId: documentId}

}

func (p *Proxy) ServeHTTP(w http.ResponseWriter, r *http.Request) {

	philter_endpoint := getEnv("PHILTER_ENDPOINT", "https://localhost:8080")
	philter_context := getEnv("PHILTER_CONTEXT", "none")
	philter_document_id := os.Getenv("PHILTER_DOCUMENT_ID")
	if philter_document_id == "" {
		philter_document_id = uuid.New().String()
	}
	philter_policy_name := getEnv("PHILTER_POLICY_NAME", "default")
	log.Println("Proxying request to " + philter_endpoint)

	if strings.HasPrefix(r.URL.Path, "/v1/messages") {
		p.handleAnthropic(w, r, philter_endpoint, philter_context, philter_document_id, philter_policy_name)
	} else if strings.Contains(r.URL.Path, ":generateContent") {
		p.handleGeminiNative(w, r, philter_endpoint, philter_context, philter_document_id, philter_policy_name)
	} else {
		p.handleOpenAI(w, r, philter_endpoint, philter_context, philter_document_id, philter_policy_name)
	}
}

func (p *Proxy) handleGeminiNative(w http.ResponseWriter, r *http.Request, philter_endpoint string, context string, documentId string, policyName string) {
	var g GeminiRequest
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(bodyBytes, &g)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for i := 0; i < len(g.Contents); i++ {
		for j := 0; j < len(g.Contents[i].Parts); j++ {
			if g.Contents[i].Parts[j].Text != "" {
				filterResponse := Filter(philter_endpoint, g.Contents[i].Parts[j].Text, context, documentId, policyName)
				g.Contents[i].Parts[j].Text = filterResponse.FilteredText
			}
		}
	}

	j, err := json.Marshal(g)
	new_body_content := string(j[:])

	r.Body = ioutil.NopCloser(strings.NewReader(new_body_content))
	r.ContentLength = int64(len(new_body_content))
	r.Host = p.geminiTarget.Host

	p.geminiProxy.ServeHTTP(w, r)
}

func (p *Proxy) handleOpenAI(w http.ResponseWriter, r *http.Request, philter_endpoint string, context string, documentId string, policyName string) {
	var o OpenAIRequest
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(bodyBytes, &o)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	for i := 0; i < len(o.Messages); i++ {
		filterResponse := Filter(philter_endpoint, o.Messages[i].Content, context, documentId, policyName)
		o.Messages[i].Content = filterResponse.FilteredText
	}

	j, err := json.Marshal(o)
	new_body_content := string(j[:])

	r.Body = ioutil.NopCloser(strings.NewReader(new_body_content))
	r.ContentLength = int64(len(new_body_content))
	r.Host = p.openaiTarget.Host

	p.openaiProxy.ServeHTTP(w, r)
}

func (p *Proxy) handleAnthropic(w http.ResponseWriter, r *http.Request, philter_endpoint string, context string, documentId string, policyName string) {
	var a AnthropicRequest
	bodyBytes, err := ioutil.ReadAll(r.Body)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	err = json.Unmarshal(bodyBytes, &a)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	// Redact system prompt
	if a.System != "" {
		filterResponse := Filter(philter_endpoint, a.System, context, documentId, policyName)
		a.System = filterResponse.FilteredText
	}

	// Redact messages
	for i := 0; i < len(a.Messages); i++ {
		switch v := a.Messages[i].Content.(type) {
		case string:
			filterResponse := Filter(philter_endpoint, v, context, documentId, policyName)
			a.Messages[i].Content = filterResponse.FilteredText
		case []any:
			// Content is an array of content blocks
			for j := 0; j < len(v); j++ {
				if block, ok := v[j].(map[string]any); ok {
					if block["type"] == "text" {
						if text, ok := block["text"].(string); ok {
							filterResponse := Filter(philter_endpoint, text, context, documentId, policyName)
							block["text"] = filterResponse.FilteredText
						}
					}
				}
			}
		}
	}

	j, err := json.Marshal(a)
	new_body_content := string(j[:])

	r.Body = ioutil.NopCloser(strings.NewReader(new_body_content))
	r.ContentLength = int64(len(new_body_content))
	r.Host = p.anthropicTarget.Host

	p.anthropicProxy.ServeHTTP(w, r)
}

func getEnv(key, fallback string) string {
	value, exists := os.LookupEnv(key)
	if !exists {
		value = fallback
	}
	return value
}

func main() {

	openaiTarget, err := url.Parse("https://api.openai.com")
	if err != nil {
		panic(err)
	}

	anthropicTarget, err := url.Parse("https://api.anthropic.com")
	if err != nil {
		panic(err)
	}

	geminiTarget, err := url.Parse("https://generativelanguage.googleapis.com")
	if err != nil {
		panic(err)
	}

	openaiProxy := httputil.NewSingleHostReverseProxy(openaiTarget)
	openaiProxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	anthropicProxy := httputil.NewSingleHostReverseProxy(anthropicTarget)
	anthropicProxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	geminiProxy := httputil.NewSingleHostReverseProxy(geminiTarget)
	geminiProxy.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	}

	p := &Proxy{
		openaiTarget:    openaiTarget,
		anthropicTarget: anthropicTarget,
		geminiTarget:    geminiTarget,
		openaiProxy:     openaiProxy,
		anthropicProxy:  anthropicProxy,
		geminiProxy:     geminiProxy,
	}

	port := getEnv("PHILTER_PROXY_PORT", "8080")
	cert_file := getEnv("PHILTER_PROXY_CERT_FILE", "cert.pem")
	key_file := getEnv("PHILTER_PROXY_KEY_FILE", "key.pem")

	fmt.Println("Started philter-ai-proxy on port " + port)
	err = http.ListenAndServeTLS(":"+port, cert_file, key_file, p)

	if err != nil {
		panic(err)
	}

}

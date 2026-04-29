# Philter AI Proxy

This project is a proxy for OpenAI, Claude, and Gemini that uses [Philter](https://philterd.ai/philter/) to remove PII, PHI, and other sensitive information from a [chat completion](https://platform.openai.com/docs/api-reference/chat), [messages](https://docs.anthropic.com/claude/reference/messages_post), or [Gemini](https://ai.google.dev/api/rest/v1beta/models/generateContent) request before sending the request to the respective API.

## How it Works

The proxy works by sending requests destined for OpenAI, Claude, or Gemini first to Philter where the sensitive information is redacted per Philter's configuration. The redacted text is then sent to the API. 

For example, if you send the following text `How old is John Smith?`, the proxy and Philter will remove the text `John Smith` from the request. The redacted request sent to the API will be `How old is REDACTED?`

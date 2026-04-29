# FAQ

### What is the Philter AI Proxy?

The Philter AI Proxy is a proxy for OpenAI, Claude, and Gemini that uses [Philter](https://philterd.ai/philter/) to remove PII, PHI, and other sensitive information from chat completion requests before they are sent to the respective AI provider.

### Why should I use it?

By using the proxy, you ensure that sensitive information never leaves your environment and is not sent to the AI providers, helping you maintain compliance and protect privacy.

### Which AI providers are supported?

Currently, the proxy supports:
* OpenAI
* Claude (Anthropic)
* Gemini (Google)

### Do I need a Philter instance?

Yes, the proxy requires a running instance of Philter to perform the redaction. You can launch one in your cloud or on-premise. Visit [philterd.ai](https://philterd.ai/philter/) for more information.

### How do I configure the proxy?

The proxy is configured via environment variables. Please refer to the [Configuration](configuration.md) page for a list of all available variables.

### Is the proxy open source?

Yes, the Philter AI Proxy is licensed under the Apache License, version 2.

### Is commercial support available?

Yes, commercial support for the Philter AI Proxy and Philter is available from [Philterd](https://www.philterd.ai). Please [contact us](https://www.philterd.ai/contact/) for more information.

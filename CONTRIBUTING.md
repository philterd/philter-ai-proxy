# Contributing to Philter AI Proxy

## Code of Conduct

In the interest of fostering an open and welcoming environment, we as contributors and maintainers pledge to making participation in our project and our community a harassment-free experience for everyone, regardless of age, body size, disability, ethnicity, gender identity and expression, level of experience, nationality, personal appearance, race, religion, or sexual identity and orientation.

Please read and understand the [Code of Conduct](https://github.com/philterd/phileas/blob/main/CODE_OF_CONDUCT.md).

## GitHub Workflow

We prefer to take contributions as GitHub pull requests. This workflow allows you to create your own copy of Philter AI Proxy, try out some changes, and then share your changes back to the community, with proper review and feedback from other contributors.

1. Create a fork of philterd/philter-ai-proxy
2. Create a feature branch
3. Build and test local changes
4. Commit changes to your feature branch
5. Open a pull request
6. Participate in code review
7. Celebrate your accomplishment

## Building and Testing Changes

### Required Tools

* Java 25 (the Maven wrapper downloads Maven)
* Docker, to build the image
* Helm, to work on the chart in `deploy/helm/`

### Testing

```
./mvnw verify          # build, run the tests, and check coverage
```

The tests run against stub providers and never call a real one. One test runs the default policy with the real `ph-eye-pii-en-small` model; it is skipped unless `PHILTER_AI_PROXY_TEST_MODELS` names a directory holding the model (see the `onnx` folder of [philterd/ph-eye-pii-en-small](https://huggingface.co/philterd/ph-eye-pii-en-small)).

`./mvnw verify` fails when line coverage drops below `coverage.minimum` in `pom.xml`. Raise that value as coverage improves; do not lower it to make a build pass.

Test fixtures use invented values only: never a real person's name, email address, or other personal data.

### The chart and manifests

After changing the Helm chart, regenerate the plain manifests with `deploy/k8s/generate.sh`. CI fails when they differ from what the chart renders.

### Contract tests

`test/contract/run.sh` runs each provider's official SDK (OpenAI, Azure OpenAI, Anthropic, Google Gen AI, boto3, and Ollama) against the proxy and a provider simulator, with a real Ollama server. It needs Docker. See `test/contract/README.md`.

### Load tests

See `test/load/README.md`.

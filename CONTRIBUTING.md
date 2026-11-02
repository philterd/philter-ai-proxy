# Contributing to Philter AI Proxy

## Licensing and sign-off

This project is licensed under [Apache 2.0](LICENSE), and contributions are accepted under the same license. Sign off every commit with `git commit -s` to certify the [Developer Certificate of Origin](https://developercertificate.org/); a required check enforces it. See the [Philterd contributing guide](https://github.com/philterd/.github/blob/main/CONTRIBUTING.md#licensing-and-sign-off) for how to sign off commits you have already made.

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

### Testing

```
./mvnw verify          # build, run the tests, and check coverage
```

The tests run against stub providers and never call a real one. One test runs the default policy with the real `ph-eye-pii-en-small` model; it is skipped unless `PHILTER_AI_PROXY_TEST_MODELS` names a directory holding the model (see the `onnx` folder of [philterd/ph-eye-pii-en-small](https://huggingface.co/philterd/ph-eye-pii-en-small)).

`./mvnw verify` fails when line coverage drops below `coverage.minimum` in `pom.xml`. Raise that value as coverage improves; do not lower it to make a build pass.

Test fixtures use invented values only: never a real person's name, email address, or other personal data.

### Contract tests

`test/contract/run.sh` runs each provider's official SDK (OpenAI, Azure OpenAI, Anthropic, Google Gen AI, boto3, and Ollama) against the proxy and a provider simulator, with a real Ollama server. It needs Docker. See `test/contract/README.md`.

### Fuzz tests

`ParserFuzzTest` fuzzes, with [Jazzer](https://github.com/CodeIntelligenceTesting/jazzer), the code that reads what clients and providers send: path decoding, the SSE, NDJSON, and AWS event stream framings, each dialect's request and response fields, and each dialect's stream reader. `./mvnw verify` runs only each target's saved inputs. To fuzz one target:

```bash
JAZZER_FUZZ=1 ./mvnw test -Dtest='ParserFuzzTest#streams' -Djacoco.skip=true -Djazzer.max_duration=5m
```

The targets are `pathDecoding`, `sse`, `ndjson`, `eventStream`, `eventStreamMessages` (AWS event stream messages with their checksums corrected), `requestFields`, `responseFields`, and `streams`. Each target's seed inputs, realistic requests, responses, and streams for every provider, are in `src/test/resources/ai/philterd/aiproxy/proxy/ParserFuzzTestInputs/<target>/`. In the field and stream targets, the input's first byte chooses the provider endpoint (`TARGETS` in the test). A crash is saved in the same directory; commit it with the fix, so it runs as a regression test. `.github/workflows/fuzz.yml` fuzzes each target for two minutes on every push and pull request.

### Load tests

See `test/load/README.md`.

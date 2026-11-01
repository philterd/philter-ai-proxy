# --- Build stage ---
FROM eclipse-temurin:25 AS build
WORKDIR /build
COPY .mvn/ .mvn/
COPY mvnw pom.xml ./
RUN ./mvnw -q -B dependency:go-offline
COPY src/ src/
RUN ./mvnw -q -B package -DskipTests

# --- Model stage ---
# The PhEye model the default policy names, ph-eye-pii-en-small, at a pinned Hugging Face revision (the one
# Philter 4.0.0 ships). Each file is checked against its SHA-256, so a changed or corrupted download fails the
# build. The model is CC-BY-4.0, so its model card, which carries the attribution the license requires, is
# shipped beside it.
FROM ubuntu:24.04 AS model
ARG PHEYE_MODEL_REVISION=375cfd7bd6b4fa0ef618333048b9e94b92c35c94
RUN apt-get update && apt-get -y install --no-install-recommends curl ca-certificates && rm -rf /var/lib/apt/lists/*
WORKDIR /model
RUN for file in gliner_config.json tokenizer.json model.onnx; do \
        curl -fsSL -o "$file" "https://huggingface.co/philterd/ph-eye-pii-en-small/resolve/${PHEYE_MODEL_REVISION}/onnx/$file"; \
    done \
    && curl -fsSL -o README.md "https://huggingface.co/philterd/ph-eye-pii-en-small/resolve/${PHEYE_MODEL_REVISION}/README.md" \
    && printf '%s\n' \
        "5ec1db300425bad5846ae36ca732bb10a404a4d4eef37f620f1184fb2561918d  gliner_config.json" \
        "a3990e1379927bc3f9321b48a37f291bb29cd975fac294030ab989f9e32458ab  tokenizer.json" \
        "0ec8b8585ee8e60334efad4206e643b9575d6bf2f9b3e93604183f8aaaf3b40d  model.onnx" \
        "b2524b6216ab14aa6c8d2b8fcdd84706f89cf6b6c4a0ff20954d6d902c0b8594  README.md" \
        | sha256sum -c -

# --- Runtime image ---
FROM eclipse-temurin:25-jre
# The upgrade picks up package fixes published since the base image was last built.
# pebble is a service manager the base image ships outside any package; the proxy does not use it.
RUN apt-get update && apt-get -y upgrade && rm -rf /var/lib/apt/lists/* && rm -f /usr/bin/pebble \
    && useradd --system --uid 10001 --home-dir /var/lib/philter-ai-proxy philter \
    && mkdir -p /var/lib/philter-ai-proxy /opt/philter-ai-proxy/models/ph-eye-pii-en-small \
    && chown philter /var/lib/philter-ai-proxy && chmod 700 /var/lib/philter-ai-proxy
COPY --from=model /model/ /opt/philter-ai-proxy/models/ph-eye-pii-en-small/
COPY --from=build /build/target/philter-ai-proxy.jar /opt/philter-ai-proxy/philter-ai-proxy.jar
COPY LICENSE /opt/philter-ai-proxy/
# The SQLite database (policies, contexts, API keys, audit log). Mount a volume here to keep it.
VOLUME /var/lib/philter-ai-proxy
USER philter
# 8080: provider traffic and the admin API. 9090: Prometheus metrics.
EXPOSE 8080 9090
# HTTPS by default, with a self-signed certificate generated at startup: no certificate is baked in, since it
# would be the same private key for everyone who pulls the image. Configure server.ssl (SERVER_SSL_CERTIFICATE and
# SERVER_SSL_CERTIFICATEPRIVATEKEY) to use your own, or set PROXY_TLS_DEVSELFSIGNEDCERT=false to serve plain HTTP
# behind a load balancer or ingress that terminates TLS.
ENV PROXY_TLS_DEVSELFSIGNEDCERT=true
ENTRYPOINT ["java", "--enable-native-access=ALL-UNNAMED", "-jar", "/opt/philter-ai-proxy/philter-ai-proxy.jar"]

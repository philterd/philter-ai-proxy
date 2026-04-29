FROM golang:1.25-alpine AS builder
RUN mkdir -p /build
WORKDIR /build
COPY . .
RUN go build

FROM debian:buster-slim
RUN set -x && apt-get update && DEBIAN_FRONTEND=noninteractive apt-get install -y \
    ca-certificates && \
    rm -rf /var/lib/apt/lists/*

RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

EXPOSE 8080
WORKDIR /app
COPY --from=builder /build/philter-ai-proxy /app/philter-ai-proxy
ENTRYPOINT ["/app/philter-ai-proxy"]
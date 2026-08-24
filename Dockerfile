# Pinned to the platform doing the building so the Go compiler runs natively and
# cross-compiles for the target, rather than running under emulation.
FROM --platform=$BUILDPLATFORM golang:1.25-alpine AS builder

# Supplied by buildx. They default to the build platform for a plain docker build.
ARG TARGETOS=linux
ARG TARGETARCH

WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
# VERSION is stamped into the binary (reported by --version). Pass it at build
# time: docker build --build-arg VERSION=v1.0.0 .  Defaults to "dev".
ARG VERSION=dev
RUN CGO_ENABLED=0 GOOS=${TARGETOS} GOARCH=${TARGETARCH} \
    go build -ldflags "-X main.version=${VERSION}" -o philter-ai-proxy .

FROM alpine:3.21
# No keypair is baked in: it would be the same private key for everyone who
# pulls the image. Set listen.cert/listen.key, or listen.devSelfSignedCert.
# ca-certificates is for outbound TLS to Philter and the providers.
RUN apk add --no-cache ca-certificates

EXPOSE 8080
WORKDIR /app
COPY --from=builder /build/philter-ai-proxy /app/philter-ai-proxy
ENTRYPOINT ["/app/philter-ai-proxy"]

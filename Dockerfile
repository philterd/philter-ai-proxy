FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN go build -o philter-ai-proxy .

FROM alpine:3.21
RUN apk add --no-cache ca-certificates openssl

RUN openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

EXPOSE 8080
WORKDIR /app
COPY --from=builder /build/philter-ai-proxy /app/philter-ai-proxy
RUN mv /cert.pem /app/cert.pem && mv /key.pem /app/key.pem
ENTRYPOINT ["/app/philter-ai-proxy"]

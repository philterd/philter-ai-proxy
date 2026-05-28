FROM golang:1.25-alpine AS builder
WORKDIR /build
COPY go.mod main.go ./
RUN go build -o stub-provider .

FROM alpine:3.21
COPY --from=builder /build/stub-provider /usr/local/bin/stub-provider
EXPOSE 8090
ENTRYPOINT ["/usr/local/bin/stub-provider"]

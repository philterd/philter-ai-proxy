# All targets are phony (no target produces a file by the same name). Without
# this, `make test` is shadowed by the test/ directory and reports
# "up to date" instead of running the tests.
.PHONY: build run cert docker-build docker-push docker-push-dry-run test cover cover-html cover-check integration-up integration-down test-integration

# Version stamped into the binary (reported by --version and logged at startup).
# Derived from the current git tag/commit; override with `make build VERSION=v1.2.3`.
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)

# Minimum statement coverage enforced by `make cover-check` and CI. Raise this
# as coverage improves; never lower it to make a build pass.
COVERAGE_THRESHOLD ?= 75

# Extra flags for the coverage test run, e.g. `make cover-check TESTFLAGS=-v`.
TESTFLAGS ?=

build:
	go build -ldflags "-X main.version=$(VERSION)" -o philter-ai-proxy .

run:
	go run .

cert:
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

docker-build:
	docker build --build-arg VERSION=$(VERSION) -t philter-ai-proxy .

docker-push:
	./docker-build-push.sh

docker-push-dry-run:
	DRY_RUN=1 ./docker-build-push.sh

test:
	go test -v ./...

cover:
	go test $(TESTFLAGS) -coverprofile=coverage.out ./...
	@go tool cover -func=coverage.out | tail -1

cover-html: cover
	go tool cover -html=coverage.out

# Fails when total statement coverage is below COVERAGE_THRESHOLD.
cover-check: cover
	@go tool cover -func=coverage.out | awk -v min=$(COVERAGE_THRESHOLD) '\
		/^total:/ { \
			pct = $$3; sub(/%/, "", pct); \
			if (pct < min) { \
				printf "FAIL: coverage %.1f%% is below the %s%% threshold\n", pct, min; \
				exit 1 \
			} \
			printf "ok: coverage %.1f%% (threshold %s%%)\n", pct, min \
		}'

integration-up:
	docker compose -f docker-compose.test.yaml up -d philter

integration-down:
	docker compose -f docker-compose.test.yaml down

test-integration: integration-up
	PHILTER_TEST_URL=http://localhost:8081 go test -v -tags=integration -run Integration ./...
	$(MAKE) integration-down
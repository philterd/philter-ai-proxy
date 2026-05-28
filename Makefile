# All targets are phony (no target produces a file by the same name). Without
# this, `make test` is shadowed by the test/ directory and reports
# "up to date" instead of running the tests.
.PHONY: build run cert docker-build docker-push docker-push-dry-run test integration-up integration-down test-integration

build:
	go build -o philter-ai-proxy .

run:
	go run .

cert:
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

docker-build:
	docker build -t philter-ai-proxy .

docker-push:
	./docker-build-push.sh

docker-push-dry-run:
	DRY_RUN=1 ./docker-build-push.sh

test:
	go test -v ./...

integration-up:
	docker compose -f docker-compose.test.yaml up -d philter

integration-down:
	docker compose -f docker-compose.test.yaml down

test-integration: integration-up
	PHILTER_TEST_URL=http://localhost:8081 go test -v -tags=integration -run Integration ./...
	$(MAKE) integration-down
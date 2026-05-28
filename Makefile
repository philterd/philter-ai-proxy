build:
	go build -o philter-ai-proxy .

run:
	go run .

cert:
	openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -sha256 -days 3650 -nodes -subj "/C=XX/ST=StateName/L=CityName/O=CompanyName/OU=CompanySectionName/CN=CommonNameOrHostname"

docker-build:
	docker build -t philter-ai-proxy .

test:
	go test -v ./...

integration-up:
	docker compose -f docker-compose.test.yaml up -d philter

integration-down:
	docker compose -f docker-compose.test.yaml down

test-integration: integration-up
	PHILTER_TEST_URL=http://localhost:8081 go test -v -tags=integration -run Integration ./...
	$(MAKE) integration-down
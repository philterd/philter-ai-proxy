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
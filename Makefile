EXEC_NAME=auto-acme

DATE_VERSION := $(shell date +%Y%m%d)
GIT_VERSION := $(shell git rev-parse --short HEAD)

LDFLAGS=-ldflags "-s -w -X main.appVersion=$(DATE_VERSION)@$(GIT_VERSION)"

all:
	go build ${LDFLAGS} ./cmd/auto-acme

crossbuild:
	test -d ./bin || mkdir ./bin
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -o bin/$(EXEC_NAME).amd64 ${LDFLAGS} ./cmd/auto-acme
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -o bin/$(EXEC_NAME).arm64 ${LDFLAGS} ./cmd/auto-acme
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o bin/$(EXEC_NAME).amd64.exe ${LDFLAGS} ./cmd/auto-acme
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o bin/$(EXEC_NAME).amd64.darwin ${LDFLAGS} ./cmd/auto-acme

clean:
	rm -rf auto-acme
	rm -f bin/$(EXEC_NAME).*

DATE_VERSION := $(shell date +%Y%m%d)
GIT_VERSION := $(shell git rev-parse --short HEAD)

all:
	go build --ldflags "-s -w -X main.appVersion=$(DATE_VERSION)@$(GIT_VERSION)" ./cmd/auto-acme

clean:
	rm -rf auto-acme

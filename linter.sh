#!/bin/sh
#https://github.com/golangci/golangci-lint/releases
# example: ./linter.sh -D unused -D deadcode
golangci-lint run -v -D errcheck $*
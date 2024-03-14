.DEFAULT_GOAL := build

build: build-dns64 build-nat64

build-dns64:
	go build -o dns64 cmd/dns64/main.go

build-nat64:
	go build -o nat64 cmd/nat64/main.go

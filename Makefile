

.PHONY: all
all:
	CGO_ENABLED=0 go build -buildvcs=auto -o bin/test_client ./cmd/test_client/
	CGO_ENABLED=0 go build -buildvcs=auto -o bin/test_server ./cmd/test_server/

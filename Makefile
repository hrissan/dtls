# Copyright (c) 2025, Grigory Buteyko aka Hrissan
# Licensed under the MIT License. See LICENSE for details.

.PHONY: all
all: ascii
	CGO_ENABLED=0 go build -buildvcs=auto -o bin/test_client ./cmd/test_client/
	CGO_ENABLED=0 go build -buildvcs=auto -o bin/test_server ./cmd/test_server/

# if found, print with
# grep -P '[^\x00-\x7F]' ./README.md
.PHONY: ascii
ascii:
	@ ! find . -not -path "./.git/*" -not -path "./bin/*" -type f -exec grep -lP '[^\x00-\x7F]' {} +

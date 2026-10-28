# rayvault — common tasks. `make` (or `make help`) lists them.

.DEFAULT_GOAL := help
.PHONY: help build test test-native fmt run interop clean

help: ## List the targets
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN {FS = ":.*## "} {printf "  %-12s %s\n", $$1, $$2}'

build: ## The native binary, ./rayvault
	rm -f rayvault
	ray build --native --release -o rayvault src/main.ray

test: ## Tests on the VM
	ray test

test-native: ## The same tests as native binaries
	ray test --native

fmt: ## Format the sources
	ray fmt -w src/*.ray tests/*.ray

run: build ## Serve with ./rayvault.toml (copy rayvault.example.toml first)
	./rayvault serve

interop: build ## A real rayauth as the issuer, TLS from an own CA, the CLI by client credentials
	scripts/interop.sh

clean: ## Remove the binary
	rm -f rayvault

.SILENT :
.PHONY : generate



vet: ## Run go vet over sources
	echo "Checking ."
	go vet -all ./...


test: vet ## Run tests
	@$(WITH_ENV) go test -v -cover -coverprofile cover.out .
	@ go tool cover -html=cover.out -o cover.out.html


generate:
	go generate ./...

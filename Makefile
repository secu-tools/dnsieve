.PHONY: build test clean all linux windows darwin cross vet coverage test-short

BINARY=dnsieve
VERSION?=$(shell if [ -f version/version_base.txt ]; then head -1 version/version_base.txt | tr -cd '0-9.'; else echo "1.0.0"; fi)
COMMIT=$(shell git rev-parse --short HEAD 2>/dev/null || echo "dev")
BUILD_NUMBER_FILE=version/build_number.txt
BUILD_NUMBER=$(shell if [ -f $(BUILD_NUMBER_FILE) ]; then cat $(BUILD_NUMBER_FILE); else echo 0; fi)
NEXT_BUILD=$(shell echo $$(( $(BUILD_NUMBER) + 1 )))
FULL_VERSION=$(VERSION).$(NEXT_BUILD)
MODULE=github.com/secu-tools/dnsieve/internal/app
LDFLAGS_BASE=-X $(MODULE).version=$(VERSION) -X $(MODULE).commit=$(COMMIT) -X $(MODULE).buildNumber=$(NEXT_BUILD) -s -w
BUILD_DIR=build

all: test build

build:
	@echo $(NEXT_BUILD) > $(BUILD_NUMBER_FILE)
	CGO_ENABLED=0 go build -ldflags "$(LDFLAGS_BASE)" -o $(BINARY)_$(FULL_VERSION) ./

test:
	go test ./... -v -count=1

test-short:
	go test ./... -count=1

coverage:
	go test ./... -coverprofile=coverage.out
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report: coverage.html"

vet:
	go vet ./...

clean:
	rm -f $(BINARY) $(BINARY).exe $(BINARY)_*
	rm -rf $(BUILD_DIR)
	rm -f coverage.out coverage.html

# Cross-compilation (delegates to build.sh for full logic)
cross:
	./build.sh -all

linux:
	./build.sh -linux

windows:
	./build.sh -windows

darwin:
	./build.sh -darwin

APP_NAME=av-switchyard
OUT_DIR=dist

VERSION ?= $(shell cat version.txt)
COMMIT ?= $(shell git rev-parse --short HEAD)
DATE ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)
BUILD_HOST ?= $(shell hostname)

LDFLAGS=-ldflags "-X av-switchyard/version.Version=$(VERSION) \
                  -X av-switchyard/version.GitCommit=$(COMMIT) \
                  -X av-switchyard/version.BuildDate=$(DATE) \
                  -X av-switchyard/version.BuildHost=$(BUILD_HOST)"

build-all: clean rsrc.syso
	-go get .

	mkdir -p $(OUT_DIR)

	$(MAKE) build-linux-amd64
	$(MAKE) build-windows-amd64
	$(MAKE) build-mac-amd64
	$(MAKE) build-mac-arm64

	# Post-compile asset copying
	mkdir -p ../testbed/vm-data/test-artifacts/
	cp $(OUT_DIR)/$(APP_NAME)-windows-amd64.exe ../testbed/vm-data/test-artifacts/


rsrc.syso:
	uv run ../graphics/render-icons-from-primary.py


build-linux-amd64:
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		go build $(LDFLAGS) -o $(OUT_DIR)/$(APP_NAME)-linux-amd64 .

build-windows-amd64: rsrc.syso
	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		go build $(LDFLAGS) -o $(OUT_DIR)/$(APP_NAME)-windows-amd64.exe .

build-mac-amd64:
	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
		go build $(LDFLAGS) -o $(OUT_DIR)/$(APP_NAME)-mac-amd64 .

build-mac-arm64:
	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
		go build $(LDFLAGS) -o $(OUT_DIR)/$(APP_NAME)-mac-arm64 .



run-linux-amd64: build-linux-amd64
	$(OUT_DIR)/$(APP_NAME)-linux-amd64 $(filter-out $@,$(MAKECMDGOALS))

run-windows-amd64: build-windows-amd64
	$(OUT_DIR)/$(APP_NAME)-windows-amd64.exe $(filter-out $@,$(MAKECMDGOALS))

run-mac-amd64: build-mac-amd64
	$(OUT_DIR)/$(APP_NAME)-mac-amd64 $(filter-out $@,$(MAKECMDGOALS))

run-mac-arm64: build-mac-arm64
	$(OUT_DIR)/$(APP_NAME)-mac-arm64 $(filter-out $@,$(MAKECMDGOALS))

%:
	@:




clean:
	-rm -rf $(OUT_DIR)
	-rm rsrc.syso
	-rm rsrc_windows_amd64.syso



APP_NAME=av-switchyard
OUT_DIR=dist

build-all: clean rsrc.syso
	-go get .

	mkdir -p $(OUT_DIR)

	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 \
		go build -o $(OUT_DIR)/$(APP_NAME)-linux-amd64 .

	GOOS=windows GOARCH=amd64 CGO_ENABLED=0 \
		go build -o $(OUT_DIR)/$(APP_NAME)-windows-amd64.exe .

	GOOS=darwin GOARCH=amd64 CGO_ENABLED=0 \
		go build -o $(OUT_DIR)/$(APP_NAME)-mac-amd64 .

	GOOS=darwin GOARCH=arm64 CGO_ENABLED=0 \
		go build -o $(OUT_DIR)/$(APP_NAME)-mac-arm64 .

	# Post-compile asset copying
	mkdir -p ../testbed/vm-data/test-artifacts/
	cp $(OUT_DIR)/$(APP_NAME)-windows-amd64.exe ../testbed/vm-data/test-artifacts/

rsrc.syso:
	uv run ../graphics/render-icons-from-primary.py

clean:
	-rm -rf $(OUT_DIR)
	-rm rsrc.syso



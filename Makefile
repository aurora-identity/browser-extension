WASM_CRATE = ./crates/aurora
EXT_DIR = ./extension
OUT_DIR = ./extension-dist
SRC_DIR = $(EXT_DIR)
# Files to minify
JS_FILES = background.js crypto.js state.js
# WASM files to copy as-is
WASM_FILES = aurora_bg.wasm aurora.js

.PHONY: build clean

build:
	rm -rf $(OUT_DIR)
	@mkdir -p $(OUT_DIR)
	@mkdir -p $(OUT_DIR)/pkg/

	@for f in $(JS_FILES); do \
		npx --yes terser $(SRC_DIR)/$$f \
			--compress \
			--mangle \
			--comments false \
			--output $(OUT_DIR)/$$f; \
	done

	# Copy JSON configs
	@cp $(SRC_DIR)/manifest.json $(SRC_DIR)/managed_schema.json $(OUT_DIR)/

	# Build WASM
	@echo "--- Building Wasm Module for Browser Extension---"
	cd $(WASM_CRATE) && wasm-pack build --release --target web --out-dir ../../extension/pkg

	# Copy WASM files as-is
	@for f in $(WASM_FILES); do \
		cp $(SRC_DIR)/pkg/$$f $(OUT_DIR)/pkg/; \
	done

	rm -rf $(EXT_DIR)/pkg
	cd $(WASM_CRATE) && cargo clean

	@echo "Done → $(OUT_DIR)/"

clean:
	rm -rf $(EXT_DIR)/pkg
	cd $(WASM_CRATE) && cargo clean
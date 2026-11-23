# Builds the Rust core as a static library for Swift and runs the Swift tests.
# macOS: universal (arm64 + x86_64) via lipo. Linux: host architecture.
CORE := $(abspath ../core)
LIBDIR := $(CORE)/target/swift
UNAME := $(shell uname)
# Rust targets for the static library; CI builds only the host architecture.
CORE_TARGETS ?= aarch64-apple-darwin x86_64-apple-darwin

.PHONY: core build test xcode clean
core:
ifeq ($(UNAME),Darwin)
	cd $(CORE) && cargo build --release -p pokey-ffi $(addprefix --target ,$(CORE_TARGETS))
	mkdir -p $(LIBDIR)
	lipo -create -output $(LIBDIR)/libpokey_ffi.a \
		$(foreach t,$(CORE_TARGETS),$(CORE)/target/$(t)/release/libpokey_ffi.a)
else
	cd $(CORE) && cargo build --release -p pokey-ffi
	mkdir -p $(LIBDIR)
	cp $(CORE)/target/release/libpokey_ffi.a $(LIBDIR)/libpokey_ffi.a
endif

build: core
	swift build -Xlinker -L$(LIBDIR)

test: core
	./scripts/make-test-bundle.sh $(LIBDIR)/testdata
	swift test -Xlinker -L$(LIBDIR)

# Signed app bundle with the system extension, daemons and agent.
xcode: core
	xcodegen generate --spec project.yml
	xcodebuild -project Pokey.xcodeproj -scheme PokeyHost -configuration Release build $(XCODEBUILD_FLAGS)

clean:
	rm -rf .build $(LIBDIR)

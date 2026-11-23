# Builds the Rust core as a static library for Swift and runs the Swift tests.
# macOS: universal (arm64 + x86_64) via lipo. Linux: host architecture.
CORE := $(abspath ../core)
LIBDIR := $(CORE)/target/swift
UNAME := $(shell uname)

.PHONY: core build test xcode clean
core:
ifeq ($(UNAME),Darwin)
	cd $(CORE) && cargo build --release -p edr-ffi --target aarch64-apple-darwin --target x86_64-apple-darwin
	mkdir -p $(LIBDIR)
	lipo -create -output $(LIBDIR)/libedr_ffi.a \
		$(CORE)/target/aarch64-apple-darwin/release/libedr_ffi.a \
		$(CORE)/target/x86_64-apple-darwin/release/libedr_ffi.a
else
	cd $(CORE) && cargo build --release -p edr-ffi
	mkdir -p $(LIBDIR)
	cp $(CORE)/target/release/libedr_ffi.a $(LIBDIR)/libedr_ffi.a
endif

build: core
	swift build -Xlinker -L$(LIBDIR)

test: core
	./scripts/make-test-bundle.sh $(LIBDIR)/testdata
	swift test -Xlinker -L$(LIBDIR)

# Signed app bundle with the system extension, daemons and agent.
xcode: core
	xcodegen generate --spec project.yml
	xcodebuild -project EDRAgent.xcodeproj -scheme EDRHost -configuration Release build $(XCODEBUILD_FLAGS)

clean:
	rm -rf .build $(LIBDIR)

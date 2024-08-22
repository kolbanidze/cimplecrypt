# Linux and MacOS only!

# Detect OS
UNAME_S := $(shell uname -s)

# Define default output directory
BIN_DIR := bin

# Define OS-specific output filenames
ifeq ($(UNAME_S), Linux)
    ENCRYPT_BINARY := $(BIN_DIR)/linux_encrypt
    DECRYPT_BINARY := $(BIN_DIR)/linux_decrypt
    STATIC_ENCRYPT_BINARY := $(BIN_DIR)/linux_static_encrypt
    STATIC_DECRYPT_BINARY := $(BIN_DIR)/linux_static_decrypt
else ifeq ($(UNAME_S), Darwin)
    ENCRYPT_BINARY := $(BIN_DIR)/macos_encrypt
    DECRYPT_BINARY := $(BIN_DIR)/macos_decrypt
else
    $(error This Makefile only supports Linux and MacOS)
endif

# Compiler and common flags
CC := gcc
CFLAGS := -Wall -Iinclude
LDFLAGS := -lsodium

# Default build target (Linux/MacOS)
.PHONY: build
build: $(ENCRYPT_BINARY) $(DECRYPT_BINARY)
	@echo "Executables saved in $(BIN_DIR)/ directory"

$(ENCRYPT_BINARY): encrypt.c cargs.c
	@echo "Building $@"
	@mkdir -p $(BIN_DIR)
	$(CC) $^ $(CFLAGS) -o $@ $(LDFLAGS)

$(DECRYPT_BINARY): decrypt.c cargs.c
	@echo "Building $@"
	@mkdir -p $(BIN_DIR)
	$(CC) $^ $(CFLAGS) -o $@ $(LDFLAGS)

# Static build target (Linux only)
.PHONY: static-build
static-build:
ifeq ($(UNAME_S), Linux)
	@echo "Building static executables."
	@mkdir -p $(BIN_DIR)
	$(CC) encrypt.c cargs.c $(CFLAGS) -o $(STATIC_ENCRYPT_BINARY) $(LDFLAGS) -static
	$(CC) decrypt.c cargs.c $(CFLAGS) -o $(STATIC_DECRYPT_BINARY) $(LDFLAGS) -static
	@echo "Static executables saved in $(BIN_DIR)/ directory"
else
	$(error Static build only supported on Linux)
endif

# Clean target (Linux/MacOS)
.PHONY: clean
clean:
	@echo "Clearing $(BIN_DIR) folder"
	@rm -rf $(BIN_DIR)/*

# Linux only.

default: build buildstatic

LIBSODIUM_VERSION_CHECK := $(shell pkg-config --modversion libsodium 2>/dev/null || echo "not installed")

check_libsodium_version:
	@if [ "$(LIBSODIUM_VERSION_CHECK)" != "not installed" ] && [ "$(LIBSODIUM_VERSION_CHECK)" \> "1.0.18" ]; then \
		echo "libsodium $(LIBSODIUM_VERSION_CHECK) was found, using it..."; \
	else \
		echo "libsodium >= 1.0.19 not found, компилируем библиотеку из исходников..."; \
		exit 1; \
	fi

build:
	@echo "Building executables."
	@mkdir -p bin
	${CC} encrypt.c cargs.c -Wall -o bin/encrypt -lsodium -Iinclude
	${CC} decrypt.c cargs.c -Wall -o bin/decrypt -lsodium -Iinclude
	@echo "Executables saved in bin/ directory"

buildstatic:
	@echo "Building executables statically."
	@mkdir -p bin
	${CC} encrypt.c cargs.c -Wall -o bin/encrypt_static -lsodium -Iinclude -static
	${CC} decrypt.c cargs.c -Wall -o bin/decrypt_static -lsodium -Iinclude -static
	@echo "Static executables saved in bin/ directory"

clean:
	@echo "Clearing bin folder"
	@rm -rf bin/*

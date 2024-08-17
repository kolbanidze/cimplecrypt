default: build
build:
	@echo "Building executables."
	@mkdir -p bin
	${CC} encrypt.c -Wall -o bin/encrypt -lsodium
	${CC} decrypt.c -Wall -o bin/decrypt -lsodium
	@echo "Executables saved in bin/ directory"

clean:
	@echo "Removing bin folder"
	@rm -rf bin

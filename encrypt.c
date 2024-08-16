#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <sodium.h>

#define KEY_LEN crypto_aead_aegis256_KEYBYTES
#define SALT_LEN crypto_pwhash_SALTBYTES
#define OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE
#define MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE
#define FILE_EXTENSION ".cc"
#define MAGIC_HEADER 0xBADC0DE

/*FILE FORMAT: 1-6 -> Header
+-------+----------------+---------------------+
| Order |      Name      |        Type         |
+-------+----------------+---------------------+
|     1 | Magic Header   | 32-bit integer (LE) |
|     2 | OPSLIMIT       | 32-bit integer (LE) |
|     3 | MEMLIMIT       | 32-bit integer (LE) |
|     4 | SALTLEN        | 8-bit integer (LE)  |
|     5 | SALT           | Bytes               |
|     6 | NONCE          | Bytes               |
|     7 | Ciphertext+tag | Bytes               |
+-------+----------------+---------------------+
P.S. LE = Little Endian
P.P.S. file will be 93 bytes larger.
*/

size_t get_file_size(const char *filename) {
    FILE *fp = fopen(filename, "rb");
    size_t size;
    if (!fp) {
        perror("Failed to open file.");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    fclose(fp);
    return size;
}

void write_file_contents_into_buffer(const char *filename, unsigned char *buffer, size_t file_size) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        perror("Failed to open file.");
        exit(EXIT_FAILURE);
    }
    fread(buffer, 1, file_size, fp);
    fclose(fp);

}

void secure_delete(const char *filename) {
    size_t file_size;
    FILE *fp = fopen(filename, "r+b");
    
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    if (!fp) {
        fprintf(stderr, "Failed to open file for secure deletion");
        return;
    }

    // First pass with zeroes
    for (size_t i = 0; i < file_size; i++) {
        fputc(0x00, fp);
    }
    fflush(fp);
    fsync(fileno(fp));
    rewind(fp);

    // Second pass with ones
    for (size_t i = 0; i < file_size; i++) {
        fputc(0xFF, fp);
    }
    fflush(fp);
    fsync(fileno(fp));
    rewind(fp);

    // Third pass with random data
    for (size_t i = 0; i < file_size; i++) {
        fputc(randombytes_random(), fp);
    }
    fflush(fp);
    fsync(fileno(fp));
    fclose(fp);

    // Erasing file name
    // I am still not sure how that code work. But it works
    char tmp[strlen(filename)];
    for (size_t i = strlen(filename); i > 0; i--) {
        char new_name[i + 1];
        for (size_t j = 0; j < i; j++) {
            new_name[j] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"[randombytes_uniform(62)];
        }
        new_name[i] = '\0';

        rename(filename, new_name);
        for (size_t j = 0; j < i+1; j++) {
            tmp[j] = new_name[j];
        }
        filename = tmp;
    }
    remove(filename);
}

int main(int argc, char *argv[]) {
    uint32_t opslimit = OPSLIMIT;
    uint32_t memlimit = MEMLIMIT;
    uint8_t saltlen = SALT_LEN;
    const uint32_t magic_header = MAGIC_HEADER;

    char *password = NULL;
    char *input_file = NULL;
    char *output_file = NULL;
    int delete_original_flag = 0;
    int secure_delete_flag = 0;
    int overwrite_file_flag = 0;
    int i_know_what_i_am_doing = 0;
    int help_flag = 0;

    if (sodium_init() < 0) {
        perror("Failed to initialize libsodium!");
        exit(EXIT_FAILURE);
    }

    // Parsing arguments
    static struct option long_options[] = {
        {"opslimit", required_argument, 0, 'c'},
        {"memlimit", required_argument, 0, 'm'},
        {"saltlen", required_argument, 0, 's'},
        {"password", required_argument, 0, 'P'},
        {"output", required_argument, 0, 'o'},
        {"delete-original", no_argument, 0, 'd'},
        {"secure-delete", no_argument, 0, 'x'},
        {"overwrite-file", no_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {"i-know-what-i-am-doing", no_argument, 0, 'Q'},
        {0, 0, 0, 0}
    };

    int opt; 
    while ((opt = getopt_long(argc, argv, "c:m:s:P:o:dxfQh", long_options, NULL)) != -1) {
        switch(opt) {
            case 'c': opslimit = atoi(optarg); break;
            case 'm': memlimit = atoi(optarg); break;
            case 's': saltlen = atoi(optarg); break;
            case 'P': password = optarg; break;
            case 'o': 
                output_file = malloc(strlen(optarg));
                if (output_file) strcpy(output_file, optarg);
                else {
                    fprintf(stderr, "Failed to allocate memory!\n"); 
                    exit(EXIT_FAILURE);
                } 
                break;
            case 'd': delete_original_flag = 1; break;
            case 'x': secure_delete_flag = 1; break;
            case 'f': overwrite_file_flag = 1; break;
            case 'h': help_flag = 1; break;
            case 'Q': i_know_what_i_am_doing = 1; break;
            default: exit(EXIT_FAILURE);
        }
    }
    if (help_flag) {
        printf("TODO\n");
        exit(EXIT_SUCCESS);
    }

    if ((opslimit < OPSLIMIT || memlimit < MEMLIMIT || saltlen < SALT_LEN) && !i_know_what_i_am_doing) {
        printf("The selected parameters are below the recommended security level. It is strongly recommended not to use the selected parameters unless you know what you are doing.\n");
        printf("If you know what you are doing, then use the --i-know-what-i-am-doing (-Q) parameter.\n");
        exit(EXIT_FAILURE);
    }
    if (opslimit < crypto_pwhash_OPSLIMIT_MIN || memlimit < crypto_pwhash_MEMLIMIT_MIN) {
        printf("The selected parameters are below the minimum security level!");
        exit(EXIT_FAILURE);
    }

    // Checking for input file
    if (optind >= argc) {
        fprintf(stderr, "Expected input file\n");
        exit(EXIT_FAILURE);
    }
    input_file = argv[optind];
    // input_file = "hello";

    // If user hasn't specified output file it will save encrypted file in {filename}.sc (if FILE_EXTENSION is .sc).
    if (!output_file) {
        output_file = malloc(strlen(input_file) + strlen(FILE_EXTENSION) + 1); // DOES IT REQUIRE +1 ????????????????????????????????????????????
        strcpy(output_file, input_file); // Copying original filename to output_file
        strcat(output_file, FILE_EXTENSION); // Concatenate filename+extension
    }

    // Check for output file existence.
    if (!overwrite_file_flag && access(output_file, F_OK) == 0) {
        fprintf(stderr, "File %s already exists. Use --overwrite-file (-f) to overwrite\n", output_file);
        exit(EXIT_FAILURE);
    }

    // Getting password without echoing it.
    if (!password) {
        password = getpass("Enter password (no echo): ");
    }
    sodium_mlock(password, strlen(password)); // Locking key in memory, so secrets won't be written to disk.

    // Generating random salt
    uint8_t salt[saltlen];
    randombytes_buf(salt, saltlen);
    // memset(salt, 0x00, saltlen);

    // Generating Argon2 key
    uint8_t key[crypto_aead_aegis256_KEYBYTES];
    sodium_mlock(key, crypto_aead_aegis256_KEYBYTES); // Locking key in memory, so secrets won't be written to disk.

    if (crypto_pwhash_argon2id(key, crypto_aead_aegis256_KEYBYTES, password, strlen(password), salt, opslimit, memlimit, crypto_pwhash_ALG_DEFAULT) == -1) {
        fprintf(stderr, "Failed to generate Argon2ID hash!");
        exit(EXIT_FAILURE);
    }
    sodium_munlock(password, strlen(password));

    // Reading file contents
    size_t file_size = get_file_size(input_file);
    unsigned char file_contents[file_size];
    write_file_contents_into_buffer(input_file, file_contents, file_size);
    sodium_mlock(file_contents, file_size);

    unsigned char ciphertext[file_size + crypto_aead_aegis256_ABYTES];
    unsigned char nonce[crypto_aead_aegis256_NPUBBYTES];
    randombytes_buf(nonce, crypto_aead_aegis256_NPUBBYTES);
    unsigned long long ciphertext_len;

    if (crypto_aead_aegis256_encrypt(ciphertext, &ciphertext_len, file_contents, file_size, NULL, 0, NULL, nonce, key) != 0) {
        fprintf(stderr, "Failed to encrypt file!\n");
        exit(EXIT_FAILURE);
    }
    
    sodium_munlock(key, crypto_aead_aegis256_KEYBYTES);
    sodium_munlock(file_contents, file_size);

    FILE *fp = fopen(output_file, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open output file!\n");
        exit(EXIT_FAILURE);
    }
    fwrite(&magic_header, sizeof(magic_header), 1, fp);
    fwrite(&opslimit, sizeof(opslimit), 1, fp);
    fwrite(&memlimit, sizeof(memlimit), 1, fp);
    fwrite(&saltlen, sizeof(saltlen), 1, fp);
    fwrite(&salt, 1, saltlen, fp);
    fwrite(&nonce, 1, crypto_aead_aegis256_NPUBBYTES, fp);
    fwrite(&ciphertext, 1, ciphertext_len, fp);
    fflush(fp);
    fclose(fp);
    printf("[Success] File %s was encrypted. Output file: %s\n", input_file, output_file);
    free(output_file);
    

    if (delete_original_flag) {
        if (remove(input_file) == 0) {
            printf("Input file was deleted.");
        }
        else {
            printf("Unable to delete input file.");
            exit(EXIT_FAILURE);
        }
    }
    
    if (secure_delete_flag) {
        secure_delete(input_file);
        sodium_memzero(input_file, strlen(input_file));
    }
    return 0;
}
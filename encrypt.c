#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <inttypes.h>
#include <cargs.h>
#include <sodium.h>
#include <string.h>
#include "utils.c"

#define KEY_LEN crypto_aead_aegis256_KEYBYTES
#define SALT_LEN crypto_pwhash_SALTBYTES
#define OPSLIMIT crypto_pwhash_OPSLIMIT_MODERATE
#define MEMLIMIT crypto_pwhash_MEMLIMIT_MODERATE
#define FILE_EXTENSION ".cc"
#define MAGIC_HEADER 0xBADC0DE
#define VERSION "1.3"
#define MAX_PASS_LEN 1024


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
P.P.S. by default file will be 93 bytes larger.
*/

static struct cag_option options[] = {
    {.identifier = 'h',
    .access_letters = "h",
    .access_name = "help",
    .description = "show this help message and exit"},

    {.identifier = 'c',
    .access_letters = "c",
    .access_name = "opslimit",
    .value_name = "OPSLIMIT",
    .description = "libsodium argon2id opslimit (cpu cycles)"},

    {.identifier = 'm',
    .access_letters = "m",
    .access_name = "memlimit",
    .value_name = "MEMLIMIT",
    .description = "libsodium argon2id memlimit (memory usage)"},

    {.identifier = 's',
    .access_letters = "s",
    .access_name = "saltlen",
    .value_name = "SALT_LENGTH",
    .description = "argon2 salt size. Default 16 bytes"},

    {.identifier = 'p',
    .access_letters = "p",
    .access_name = "password",
    .value_name = "PASSWORD",
    .description = "password"},

    {.identifier = 'o',
    .access_letters = "o",
    .access_name = "output",
    .value_name = "OUTPUT",
    .description = "output file"},

    {.identifier = 'Q',
    .access_letters = "Q",
    .access_name = "i-know-what-i-am-doing",
    .description = "use KDF parameters values less than recommended"},

    {.identifier = 'd',
    .access_letters = "d",
    .access_name = "delete",
    .description = "delete original (unencrypted) file without overwriting (not secure)"},

    {.identifier = 'x',
    .access_letters = "x",
    .access_name = "secure-delete",
    .description = "delete original (unencrypted) file with US DoD 5220.22-M 3 pass"},

    {.identifier = 'f',
    .access_letters = "f",
    .access_name = "overwrite-file",
    .description = "if directory contains 'test.cc' that parameter will allow overwriting"},

    {.identifier = 'v',
    .access_letters = "v",
    .access_name = "version",
    .description = "shows version"}
};

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

    if (sodium_init() < 0) {
        perror("Failed to initialize libsodium!");
        exit(EXIT_FAILURE);
    }

    // Parsing parameters
    cag_option_context context;
    cag_option_init(&context, options, CAG_ARRAY_SIZE(options), argc, argv);
    while (cag_option_fetch(&context)) {
    switch (cag_option_get_identifier(&context)) {
        case 'c':
            opslimit = atoi(cag_option_get_value(&context));
            break;
        case 'm':
            memlimit = atoi(cag_option_get_value(&context));
            break;
        case 's':
            saltlen = atoi(cag_option_get_value(&context));
            break;
        case 'p':
            password = strdup(cag_option_get_value(&context));
            break;
        case 'o':
            output_file = strdup(cag_option_get_value(&context));
            break;
        case 'Q':
            i_know_what_i_am_doing = 1;
            break;
        case 'd':
            delete_original_flag = 1;
            break;
        case 'x':
            secure_delete_flag = 1;
            break;
        case 'f':
            overwrite_file_flag = 1;
            break;
        case 'v':
            printf("Version: %s\n", VERSION);
            return EXIT_SUCCESS;
        case 'h':
            printf("Usage: encrypt [OPTIONS] file\n");
            cag_option_print(options, CAG_ARRAY_SIZE(options), stdout);
            return EXIT_SUCCESS;
        case '?':
            cag_option_print_error(&context, stdout);
            break;
        }
    }
    input_file = argv[cag_option_get_index(&context)];
    // input_file = "encryptme.txt";

    if (!input_file) {
        fprintf(stderr, "Expected input file!\n");
        exit(EXIT_FAILURE);
    }
    
    // Check if input_file is directory
    if (is_directory(input_file)) {
        fprintf(stderr, "The selected file is a directory. Please select a file.\n");
        return EXIT_FAILURE;
    }

    if ((opslimit < OPSLIMIT || memlimit < MEMLIMIT || saltlen < SALT_LEN) && !i_know_what_i_am_doing) {
        printf("The selected parameters are below the recommended security level. It is strongly recommended not to use the selected parameters unless you know what you are doing.\n");
        printf("If you know what you are doing, then use the --i-know-what-i-am-doing (-Q) parameter.\n");
        exit(EXIT_FAILURE);
    }
    if (opslimit < crypto_pwhash_OPSLIMIT_MIN || memlimit < crypto_pwhash_MEMLIMIT_MIN || saltlen < 8) {
        printf("The selected parameters are below the minimum security level!");
        exit(EXIT_FAILURE);
    }

    // If user hasn't specified output file it will save encrypted file in {filename}.sc (if FILE_EXTENSION is .sc).
    if (!output_file) {
        output_file = malloc(strlen(input_file) + strlen(FILE_EXTENSION) + 1);
        strcpy(output_file, input_file); // Copying original filename to output_file
        strcat(output_file, FILE_EXTENSION); // Concatenate filename+extension
    }
    
    // Check for output file existence.
    FILE *file_existence = fopen(output_file, "rb");
    if (!overwrite_file_flag && file_existence) {
        fprintf(stderr, "File %s already exists. Use --overwrite-file (-f) to overwrite\n", output_file);
        fclose(file_existence);
        exit(EXIT_FAILURE);
    }

    // Getting password without echoing it.
    if (!password) {
        password = getpass_secure("Enter password (no echo): ");
    }
    sodium_mlock(password, strlen(password)); // Locking key in memory, so secrets won't be written to disk.

    // Generating random salt
    uint8_t *salt = malloc(saltlen);
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
    FILE *fp = fopen(input_file, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file.");
        exit(EXIT_FAILURE);
    }
    size_t file_size;
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);
    unsigned char *file_contents = malloc(file_size);
    // write_file_contents_into_buffer(input_file, file_contents, file_size);
    fread(file_contents, 1, file_size, fp);
    fclose(fp);
    sodium_mlock(file_contents, file_size);

    unsigned char *ciphertext = malloc(file_size + crypto_aead_aegis256_ABYTES);
    unsigned char nonce[crypto_aead_aegis256_NPUBBYTES];
    randombytes_buf(nonce, crypto_aead_aegis256_NPUBBYTES);
    unsigned long long ciphertext_len;

    if (crypto_aead_aegis256_encrypt(ciphertext, &ciphertext_len, file_contents, file_size, NULL, 0, NULL, nonce, key) != 0) {
        fprintf(stderr, "Failed to encrypt file!\n");
        exit(EXIT_FAILURE);
    }
    
    sodium_munlock(key, crypto_aead_aegis256_KEYBYTES);
    sodium_munlock(file_contents, file_size);

    fp = fopen(output_file, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to open output file!\n");
        exit(EXIT_FAILURE);
    }
    if (fwrite(&magic_header, sizeof(magic_header), 1, fp) != 1) {
        printf("Failed to write magic header to encrypted file!\n");
        sodium_memzero(&input_file, strlen(input_file));
        exit(EXIT_FAILURE);
    }
    if (fwrite(&opslimit, sizeof(opslimit), 1, fp) != 1) {
        printf("Failed to write opslimit to encrypted file!\n");
        sodium_memzero(&input_file, strlen(input_file));
        exit(EXIT_FAILURE);
    }
    if (fwrite(&memlimit, sizeof(memlimit), 1, fp) != 1) {
        printf("Failed to write memlimit to encrypted file!\n");
        sodium_memzero(&input_file, strlen(input_file));
        exit(EXIT_FAILURE);
    }
    if (fwrite(&saltlen, sizeof(saltlen), 1, fp) != 1) {
        printf("Failed to write saltlen to encrypted file!\n");
        sodium_memzero(&input_file, strlen(input_file));
        exit(EXIT_FAILURE);
    }
    if (fwrite(salt, 1, saltlen, fp) != saltlen) {
        printf("Failed to write salt to encrypted file!\n");
        sodium_memzero(&input_file, strlen(input_file));
        exit(EXIT_FAILURE);
    }
    if (fwrite(nonce, 1, crypto_aead_aegis256_NPUBBYTES, fp) != crypto_aead_aegis256_NPUBBYTES) {
        printf("Failed to write salt to encrypted file!\n");
        sodium_memzero(&input_file, strlen(input_file));
        exit(EXIT_FAILURE);
    }
    if (fwrite(ciphertext, 1, ciphertext_len, fp) != ciphertext_len) {
        printf("Failed to write ciphertext to encrypted file!\n");
        sodium_memzero(&input_file, strlen(input_file));
        exit(EXIT_FAILURE);
    }
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
        sodium_memzero(&input_file, strlen(input_file));
    }
    return 0;
}

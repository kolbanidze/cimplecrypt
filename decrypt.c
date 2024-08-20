#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <stdint.h>
#include <sodium.h>
#include <string.h>
#include <cargs.h>
#include "utils.c"

#define FILE_EXTENSION ".cc"
#define MAGIC_HEADER 0xBADC0DE
#define VERSION "1.3"

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

    {.identifier = 'd',
    .access_letters = "d",
    .access_name = "delete",
    .description = "delete original (encrypted) file without overwriting (not secure)"},

    {.identifier = 'x',
    .access_letters = "x",
    .access_name = "secure-delete",
    .description = "delete original (encrypted) file with US DoD 5220.22-M 3 pass"},

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
    // Executing sodium_init() to ensure libsodium works correctly
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium!\n");
        return EXIT_FAILURE;
    }

    // Initialization of pointers and flags
    char *input_file = NULL;
    char *output_file = NULL;
    char *password = NULL;
    int delete_original_flag = 0;
    int secure_delete_flag = 0;
    int overwrite_file_flag = 0;

    const uint32_t magic_header = MAGIC_HEADER;
    
    // Parsing cli parameters
    cag_option_context context;
    cag_option_init(&context, options, CAG_ARRAY_SIZE(options), argc, argv);
    while (cag_option_fetch(&context)) {
        switch (cag_option_get_identifier(&context)) {
            case 'p':
                password = strdup(cag_option_get_value(&context));
                break;
            case 'o':
                output_file = strdup(cag_option_get_value(&context));
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
                printf("Usage: decrypt [OPTIONS] file\n");
                cag_option_print(options, CAG_ARRAY_SIZE(options), stdout);
                return EXIT_SUCCESS;
            case '?':
                cag_option_print_error(&context, stdout);
                break;
        }
    }
    input_file = argv[cag_option_get_index(&context)];
    // input_file = "hello.txt.cc";
    if (!input_file) {
        fprintf(stderr, "Expected input file!");
        return EXIT_FAILURE;
    }

    // Check if input_file is directory
    if (is_directory(input_file)) {
        fprintf(stderr, "The selected file is a directory. Please select a file.\n");
        return EXIT_FAILURE;
    }
    // Check if both -d and -x were used
    if (delete_original_flag && secure_delete_flag) {
        printf("You have selected both delete and securely delete. The program will assume that original file needs to be securely deleted.");
        delete_original_flag = 0;
    }
    
    FILE *fp = fopen(input_file, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file.\n");
        return EXIT_FAILURE;
    }

    // If the user has not selected a file output and the file has a standard extension (.cc), the program will use a file without an extension (.cc) as output.
    // If the file does not have a standard extension, the program will require you to specify the file output.
    if (!output_file) {
        char *extension = NULL;
        extension = strrchr(input_file, '.');
        if (extension != NULL) {
            if (strcmp(extension, FILE_EXTENSION) == 0) {
                size_t output_size = strlen(input_file)-3;
                output_file = malloc(output_size+1);
                strncpy(output_file, input_file, output_size);
                output_file[output_size] = '\0';
            }
            else {
                fprintf(stderr, "Selected file doesn't have %s extension. Select output file!\n", FILE_EXTENSION);
                return EXIT_FAILURE;
            }
        }
        else {
            fprintf(stderr, "Selected file doesn't have %s extension. Select output file!\n", FILE_EXTENSION);
            return EXIT_FAILURE;
        }
    }

    // Checking if output file already exists.
    FILE *file_existence = fopen(output_file, "rb");
    if (!overwrite_file_flag && file_existence) {
        fprintf(stderr, "File %s already exists. Use --overwrite-file (-f) to overwrite\n", output_file);
        fclose(file_existence);
        return EXIT_FAILURE;
    }
    
    // Getting password without echoing it.
    if (!password) {
        password = getpass_secure("Enter password (no echo): ");
    }
    sodium_mlock(password, strlen(password));

    // Getting file size
    size_t size;
    fseek(fp, 0, SEEK_END);
    size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // Parsing encrypted file
    uint32_t opslimit, memlimit, file_magic_header;
    uint8_t saltlen;
    fread(&file_magic_header, 1, sizeof(magic_header), fp);
    if (magic_header != file_magic_header) {
        fprintf(stderr, "The file is corrupted or is not an encrypted cimplecrypt file.\n");
        sodium_munlock(password, strlen(password));
        fclose(fp);
        return EXIT_FAILURE;
    } 
    fread(&opslimit, 1, sizeof(opslimit), fp);
    fread(&memlimit, 1, sizeof(memlimit), fp);
    fread(&saltlen, 1, sizeof(saltlen), fp);
    unsigned char *salt = malloc(saltlen);
    unsigned char nonce[crypto_aead_aegis256_NPUBBYTES];
    const long long textlen = size-sizeof(magic_header)-sizeof(opslimit)-sizeof(memlimit)-sizeof(saltlen)-saltlen-crypto_aead_aegis256_NPUBBYTES-32;
    unsigned char *ciphertext_and_mac = malloc(textlen+32);
    unsigned char *plaintext = malloc(textlen);

    fread(salt, 1, saltlen, fp);
    fread(&nonce, 1, crypto_aead_aegis256_NPUBBYTES, fp);
    fread(ciphertext_and_mac, 1, textlen+32, fp);
    fclose(fp);
    
    // Generating Argon2 key
    uint8_t key[crypto_aead_aegis256_KEYBYTES];
    sodium_mlock(key, crypto_aead_aegis256_KEYBYTES);

    if (crypto_pwhash_argon2id(key, crypto_aead_aegis256_KEYBYTES, password, strlen(password), salt, opslimit, memlimit, crypto_pwhash_ALG_DEFAULT) == -1) {
        fprintf(stderr, "Failed to generate Argon2ID hash! Check file integrity and password.\n");
        sodium_munlock(key, crypto_aead_aegis256_KEYBYTES);
        sodium_munlock(password, strlen(password));
        return EXIT_FAILURE;
    }
    sodium_munlock(password, strlen(password));
    
    unsigned long long length;
    if (crypto_aead_aegis256_decrypt(plaintext, &length, NULL, ciphertext_and_mac, textlen+32, NULL, 0, nonce, key) != 0) {
        fprintf(stderr, "Failed to decrypt!\n");
        return EXIT_FAILURE;
    }

    // Writing plaintext to output file
    fp = fopen(output_file, "wb");
    if (!fp) {
        fprintf(stderr, "Failed to create output file!\n");
        return EXIT_FAILURE;
    }
    fwrite(plaintext, sizeof(unsigned char), textlen, fp);
    fclose(fp);
    printf("[Success] File '%s' was decrypted. Output file: '%s'\n", input_file, output_file);
    free(output_file);

    if (delete_original_flag) {
        if (remove(input_file) == 0) {
            printf("Input file was deleted.");
        }
        else {
            printf("Unable to delete input file.");
            return EXIT_FAILURE;
        }
    }
    
    if (secure_delete_flag) {
        secure_delete(input_file);
    }
    return 0;
}
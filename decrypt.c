#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdint.h>
#include <getopt.h>
#include <sodium.h>

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
P.P.S. by default file will be 93 bytes larger.
*/

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
    // Executing sodium_init() to ensure libsodium works correctly
    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium!\n");
        exit(1);
    }

    // Initialization of pointers and flags
    char *input_file = NULL;
    char *output_file = NULL;
    char *password = NULL;
    int delete_original_flag = 0;
    int secure_delete_flag = 0;
    int overwrite_flag = 0;
    int help_flag = 0;

    const uint32_t magic_header = MAGIC_HEADER;
    
    // Parsing cli parameters
    static struct option long_options[] = {
        {"output", required_argument, 0, 'o'},
        {"password", required_argument, 0, 'P'},
        {"delete-original", no_argument, 0, 'd'},
        {"secure-delete", no_argument, 0, 'x'},
        {"overwrite-file", no_argument, 0, 'f'},
        {"help", no_argument, 0, 'h'},
        {0, 0, 0, 0}
    };
    
    int opt;
    while ((opt = getopt_long(argc, argv, "o:P:dxfh", long_options, NULL)) != -1) {
        switch(opt) {
            case 'o': 
                output_file = malloc(strlen(optarg)+1);
                if (output_file) strcpy(output_file, optarg);
                else {
                    fprintf(stderr, "Failed to allocate memory\n!");
                    exit(EXIT_FAILURE);
                }
                break;
            case 'P': password = optarg; break;
            case 'd': delete_original_flag = 1; break;
            case 'x': secure_delete_flag = 1; break;
            case 'f': overwrite_flag = 1; break;
            case 'h': help_flag = 1; break;
            default: exit(EXIT_FAILURE);
        }
    }

    // Displaying help
    if (help_flag) {
        printf("usage: decrypt  [-h] [-P PASSWORD] [-o OUTPUT] [-d | --delete]\n");
        printf("                [-x | --secure-delete] [-f | --overwrite-file]\n");
        printf("                file\n\n");
        printf("Simple decryption tool in C. KDF: Argon2 (ID). Symmetric cipher: AEGIS-256\n\n");
        printf("positional arguments:\n  file                  file to encrypt\n\n");
        printf("options:\n");
        printf("  -h, --help            show this help message and exit\n");
        printf("  -P PASSWORD, --password PASSWORD\n                        password\n");
        printf("  -o OUTPUT, --output OUTPUT\n                        output file\n");
        printf("  -d, --delete          delete original (unencrypted) file without overwriting\n                        (not secure)\n");
        printf("  -x, --secure-delete   delete original (unencrypted) file with US DoD\n                        5220.22-M 3 pass\n");
        printf("  -f, --overwrite-file  when you try to encrypt 'test' but directory contains\n                        'test%s' that parameter will allow overwriting\n                        'test%s'\n", FILE_EXTENSION, FILE_EXTENSION);
        exit(EXIT_SUCCESS);
    }

    // Checking for input file
    if (optind >= argc) {
        fprintf(stderr, "Expected input file\n");
        exit(EXIT_FAILURE);
    }
    input_file = argv[optind];
    // input_file = "test.c";
    // output_file = "halo";

    // Check if both -d and -x were used
    if (delete_original_flag && secure_delete_flag) {
        printf("You have selected both delete and securely delete. The program will assume that original file needs to be securely deleted.");
        delete_original_flag = 0;
    }
    
    FILE *fp = fopen(input_file, "rb");
    if (!fp) {
        fprintf(stderr, "Failed to open file.\n");
        exit(EXIT_FAILURE);
    }

    // Checking if output file already exists.
    if ((access(output_file, F_OK) == 0) && !overwrite_flag) {
        printf("File %s already exists. Use -f to overwrite\n.", output_file);
        exit(EXIT_FAILURE);
    }

    // Getting password without echoing it.
    if (!password) {
        password = getpass("Enter password (no echo): ");
    }
    sodium_mlock(password, strlen(password));

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
                exit(EXIT_FAILURE);
            }
        }
        else {
            fprintf(stderr, "Selected file doesn't have %s extension. Select output file!\n", FILE_EXTENSION);
            exit(EXIT_FAILURE);
        }
    }

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
        exit(EXIT_FAILURE);
    } 
    fread(&opslimit, 1, sizeof(opslimit), fp);
    fread(&memlimit, 1, sizeof(memlimit), fp);
    fread(&saltlen, 1, sizeof(saltlen), fp);
    unsigned char salt[saltlen];
    unsigned char nonce[crypto_aead_aegis256_NPUBBYTES];
    const long long textlen = size-sizeof(magic_header)-sizeof(opslimit)-sizeof(memlimit)-sizeof(saltlen)-saltlen-crypto_aead_aegis256_NPUBBYTES-32;
    unsigned char ciphertext_and_mac[textlen+32];
    unsigned char plaintext[textlen];

    fread(&salt, 1, saltlen, fp);
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
        exit(EXIT_FAILURE);
    }
    sodium_munlock(password, strlen(password));
    
    unsigned long long length;
    if (crypto_aead_aegis256_decrypt(plaintext, &length, NULL, ciphertext_and_mac, textlen+32, NULL, 0, nonce, key) != 0) {
        fprintf(stderr, "Failed to decrypt!\n");
        exit(EXIT_FAILURE);
    }

    // Writing plaintext to output file
    fp = fopen(output_file, "wb");
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
            exit(EXIT_FAILURE);
        }
    }
    
    if (secure_delete_flag) {
        secure_delete(input_file);
    }
    return 0;
}
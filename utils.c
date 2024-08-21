#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <windows.h>
#else
#include <termios.h>
#include <unistd.h>
#include <sys/stat.h>
#endif

// If you change that parameter you need to change scanf in getpass_secure function to MAX_PASS_LEN-1
#define MAX_PASS_LEN 1024
#define RANDOM_CHARSET "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789"

int is_directory(const char *filename) {
#ifdef _WIN32
    DWORD fileAttributes = GetFileAttributesA(filename);
    if (fileAttributes == INVALID_FILE_ATTRIBUTES) {
        return 0; // File not found or another error
    }
    return (fileAttributes & FILE_ATTRIBUTE_DIRECTORY) ? 1 : 0;
#else
    struct stat path_stat;
    if (stat(filename, &path_stat) != 0) {
        return 0; // File not found or another error
    }
    return S_ISDIR(path_stat.st_mode) ? 1 : 0;
#endif
}

void disable_echo() {
#ifndef _WIN32
    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt); // Get current terminal attributes
    newt = oldt;
    newt.c_lflag &= ~ECHO; // Disable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &newt); // Set the new attributes
#endif
}

void restore_echo() {
#ifndef _WIN32
    struct termios oldt;
    tcgetattr(STDIN_FILENO, &oldt); // Get current terminal attributes
    oldt.c_lflag |= ECHO; // Re-enable echo
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt); // Set the restored attributes
#endif
}

char *getpass_secure(const char *prompt) {
    static char password[MAX_PASS_LEN];
    sodium_memzero(password, MAX_PASS_LEN);

#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode;

    // Get the current console mode
    GetConsoleMode(hStdin, &mode);
    // Disable echo input
    SetConsoleMode(hStdin, mode & ~(ENABLE_ECHO_INPUT));

    // Prompt the user for the password
    printf("%s", prompt);
    fgets(password, MAX_PASS_LEN, stdin);

    // Restore the original console mode
    SetConsoleMode(hStdin, mode);
    printf("\n");
#else
    // Disable echo on Unix-like systems
    printf("%s", prompt);
    fflush(stdout);
    disable_echo();

    scanf("%1023s", password);

    // Restore terminal settings
    restore_echo();
    printf("\n");
#endif

    // Remove newline character if present
    size_t len = strlen(password);
    if (len > 0 && password[len - 1] == '\n') {
        password[len - 1] = '\0';
    }

    return password;
}

void random_rename(const char *filename) {
    int name_len = strlen(filename);
    char *new_name = malloc(name_len + 1);
    char *current_name = strdup(filename); // Keep track of the current file name
    if (!new_name || !current_name) {
        fprintf(stderr, "Failed to allocate memory for random renaming!\n");
        free(new_name);
        free(current_name);
        return;
    }

    if (sodium_init() < 0) {
        fprintf(stderr, "Failed to initialize libsodium\n");
        free(new_name);
        free(current_name);
        return;
    }

    for (int i = 0; i < name_len; i++) {
        // Generate a random name using libsodium
        for (int j = 0; j < name_len; j++) {
            new_name[j] = RANDOM_CHARSET[randombytes_uniform(sizeof(RANDOM_CHARSET) - 1)];
        }
        new_name[name_len] = '\0';

        // Rename the file
        if (rename(current_name, new_name) != 0) {
            perror("Error renaming file");
            free(new_name);
            free(current_name);
            return;
        }

        // Update the current file name for the next iteration
        strcpy(current_name, new_name);
    }

    // Finally, delete the file
    if (remove(current_name) != 0) {
        perror("Error deleting file");
    }

    free(new_name);
    free(current_name);
}

void secure_delete(const char *filename) {
    size_t file_size;
    FILE *fp = fopen(filename, "r+b");
    if (!fp) {
        perror("An error occurred while securely deleting the file");
        exit(EXIT_FAILURE);
    }
    fseek(fp, 0, SEEK_END);
    file_size = ftell(fp);
    fseek(fp, 0, SEEK_SET);

    // First pass with zeroes
    for (size_t i = 0; i < file_size; i++) {
        fputc(0x00, fp);
    }
    fflush(fp);
    rewind(fp);

    // Second pass with ones
    for (size_t i = 0; i < file_size; i++) {
        fputc(0xFF, fp);
    }
    fflush(fp);
    rewind(fp);

    // Third pass with random data
    for (size_t i = 0; i < file_size; i++) {
        fputc(randombytes_random(), fp);
    }
    fflush(fp);
    fclose(fp);

    random_rename(filename);
}

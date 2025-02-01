#include "linuxcrypter.h"
#include "crypto_utils.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

/* File I/O Helper Functions */
static uint8_t* read_file(const char *filename, size_t *length) {
    FILE *fp = fopen(filename, "rb");
    if (!fp) {
        return NULL;
    }
    fseek(fp, 0, SEEK_END);
    long file_size = ftell(fp);
    if (file_size < 0) {
        fclose(fp);
        return NULL;
    }
    fseek(fp, 0, SEEK_SET);
    /* Allocate extra 16 bytes for possible padding */
    uint8_t *data = malloc(file_size + 16);
    if (!data) {
        fclose(fp);
        return NULL;
    }
    size_t read_bytes = fread(data, 1, file_size, fp);
    fclose(fp);
    if (read_bytes != (size_t)file_size) {
        free(data);
        return NULL;
    }
    *length = file_size;
    return data;
}

static int write_file(const char *filename, uint8_t *data, size_t length) {
    FILE *fp = fopen(filename, "wb");
    if (!fp) {
        return -1;
    }
    size_t written = fwrite(data, 1, length, fp);
    fclose(fp);
    return (written == length) ? 0 : -1;
}

/* Generate random IV using /dev/urandom */
static int generate_random_iv(uint8_t *iv) {
    FILE *urandom = fopen("/dev/urandom", "rb");
    if (!urandom) {
        return -1;
    }
    size_t read = fread(iv, 1, 16, urandom);
    fclose(urandom);
    return (read == 16) ? 0 : -1;
}

static void usage(const char *progname) {
    printf("Usage:\n");
    printf("  %s -e <input_file> <output_file> <key_file>  (encryption)\n", progname);
    printf("  %s -d <input_file> <output_file> <key_file>  (decryption)\n", progname);
}

#ifndef UNIT_TESTS
int main(int argc, char *argv[]) {
    if (argc != 5) {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    int do_encrypt = 0, do_decrypt = 0;
    if (strcmp(argv[1], "-e") == 0) {
        do_encrypt = 1;
    } else if (strcmp(argv[1], "-d") == 0) {
        do_decrypt = 1;
    } else {
        usage(argv[0]);
        return EXIT_FAILURE;
    }
    
    /* Read input file */
    size_t file_length;
    uint8_t *file_data = read_file(argv[2], &file_length);
    if (!file_data) {
        fprintf(stderr, "Error reading input file.\n");
        return EXIT_FAILURE;
    }
    
    /* Read key from key file */
    size_t key_length;
    uint8_t *key_data = read_file(argv[4], &key_length);
    if (!key_data || key_length != 32) {
        fprintf(stderr, "Error reading key file (must be exactly 32 bytes).\n");
        free(file_data);
        return EXIT_FAILURE;
    }
    
    EncryptionContext ctx;
    /* Initialize key schedule */
    if (init_aes_key_schedule(&ctx.key_schedule, key_data) != 0) {
        fprintf(stderr, "Error initializing key schedule.\n");
        free(file_data);
        free(key_data);
        return EXIT_FAILURE;
    }
    
    /* Generate random IV for encryption, read from file for decryption */
    if (do_encrypt) {
        if (generate_random_iv(ctx.iv) != 0) {
            fprintf(stderr, "Error generating random IV.\n");
            cleanup_key_schedule(&ctx.key_schedule);
            free(file_data);
            free(key_data);
            return EXIT_FAILURE;
        }
    } else {
        /* For decryption, read IV from start of file */
        if (file_length < 16) {
            fprintf(stderr, "Input file too short (must contain at least IV).\n");
            cleanup_key_schedule(&ctx.key_schedule);
            free(file_data);
            free(key_data);
            return EXIT_FAILURE;
        }
        memcpy(ctx.iv, file_data, 16);
        /* Adjust data pointer and length to skip IV */
        memmove(file_data, file_data + 16, file_length - 16);
        file_length -= 16;
    }
    
    ctx.mode = 1;  /* Set to 1 for CBC mode (use 2 for CTR mode) */
    
    DataBuffer buffer;
    buffer.data = file_data;
    buffer.length = file_length;
    
    lc_error_t result;
    if (do_encrypt) {
        result = encrypt_data(&ctx, &buffer);
        if (result != LC_SUCCESS) {
            fprintf(stderr, "Encryption failed with error code: %d\n", result);
            cleanup_key_schedule(&ctx.key_schedule);
            free(file_data);
            free(key_data);
            return EXIT_FAILURE;
        }
        
        /* For encryption, we need to prepend the IV to the output */
        FILE *fp = fopen(argv[3], "wb");
        if (!fp) {
            fprintf(stderr, "Error opening output file.\n");
            cleanup_key_schedule(&ctx.key_schedule);
            free(file_data);
            free(key_data);
            return EXIT_FAILURE;
        }
        
        /* Write IV first */
        if (fwrite(ctx.iv, 1, 16, fp) != 16) {
            fprintf(stderr, "Error writing IV to output file.\n");
            fclose(fp);
            cleanup_key_schedule(&ctx.key_schedule);
            free(file_data);
            free(key_data);
            return EXIT_FAILURE;
        }
        
        /* Then write encrypted data */
        if (fwrite(buffer.data, 1, buffer.length, fp) != buffer.length) {
            fprintf(stderr, "Error writing encrypted data to output file.\n");
            fclose(fp);
            cleanup_key_schedule(&ctx.key_schedule);
            free(file_data);
            free(key_data);
            return EXIT_FAILURE;
        }
        fclose(fp);
    } else if (do_decrypt) {
        result = decrypt_data(&ctx, &buffer);
        if (result != LC_SUCCESS) {
            fprintf(stderr, "Decryption failed with error code: %d\n", result);
            cleanup_key_schedule(&ctx.key_schedule);
            free(file_data);
            free(key_data);
            return EXIT_FAILURE;
        }
        
        /* Write decrypted data */
        if (write_file(argv[3], buffer.data, buffer.length) != 0) {
            fprintf(stderr, "Error writing output file.\n");
            cleanup_key_schedule(&ctx.key_schedule);
            free(file_data);
            free(key_data);
            return EXIT_FAILURE;
        }
    }
    
    /* Clean up */
    cleanup_key_schedule(&ctx.key_schedule);
    free(file_data);
    free(key_data);
    
    printf("%sion completed successfully.\n", do_encrypt ? "Encrypt" : "Decrypt");
    return EXIT_SUCCESS;
}

#else  /* UNIT_TESTS defined */

/* Unit Tests */
#include <assert.h>

static void test_empty_input(void) {
    EncryptionContext ctx;
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
    assert(init_aes_key_schedule(&ctx.key_schedule, key) == 0);
    for (int i = 0; i < 16; i++) ctx.iv[i] = (uint8_t)(0xA1 + i);
    ctx.mode = 1;
    
    DataBuffer buffer;
    buffer.data = malloc(16);
    buffer.length = 0;
    
    lc_error_t res = encrypt_data(&ctx, &buffer);
    assert(res == LC_SUCCESS);
    /* Empty input produces one block with full padding */
    assert(buffer.length == 16);
    
    res = decrypt_data(&ctx, &buffer);
    assert(res == LC_SUCCESS);
    assert(buffer.length == 0);
    
    free(buffer.data);
    cleanup_key_schedule(&ctx.key_schedule);
}

static void test_single_block_encryption(void) {
    EncryptionContext ctx;
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
    assert(init_aes_key_schedule(&ctx.key_schedule, key) == 0);
    for (int i = 0; i < 16; i++) ctx.iv[i] = (uint8_t)(0xA1 + i);
    ctx.mode = 1;
    
    uint8_t plaintext[16];
    for (int i = 0; i < 16; i++) plaintext[i] = (uint8_t)i;
    
    DataBuffer buffer;
    buffer.data = malloc(32);  /* Space for two blocks */
    memcpy(buffer.data, plaintext, 16);
    buffer.length = 16;
    
    lc_error_t res = encrypt_data(&ctx, &buffer);
    assert(res == LC_SUCCESS);
    assert(buffer.length == 32);  /* Original block plus padding block */
    
    res = decrypt_data(&ctx, &buffer);
    assert(res == LC_SUCCESS);
    assert(buffer.length == 16);
    assert(memcmp(buffer.data, plaintext, 16) == 0);
    
    free(buffer.data);
    cleanup_key_schedule(&ctx.key_schedule);
}

static void test_partial_block_padding(void) {
    EncryptionContext ctx;
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
    assert(init_aes_key_schedule(&ctx.key_schedule, key) == 0);
    for (int i = 0; i < 16; i++) ctx.iv[i] = (uint8_t)(0xA1 + i);
    ctx.mode = 1;
    
    uint8_t plaintext[20];
    for (int i = 0; i < 20; i++) plaintext[i] = (uint8_t)i;
    
    DataBuffer buffer;
    buffer.data = malloc(32);
    memcpy(buffer.data, plaintext, 20);
    buffer.length = 20;
    
    lc_error_t res = encrypt_data(&ctx, &buffer);
    assert(res == LC_SUCCESS);
    assert(buffer.length == 32);
    
    res = decrypt_data(&ctx, &buffer);
    assert(res == LC_SUCCESS);
    assert(buffer.length == 20);
    assert(memcmp(buffer.data, plaintext, 20) == 0);
    
    free(buffer.data);
    cleanup_key_schedule(&ctx.key_schedule);
}

static void test_invalid_padding_decryption(void) {
    EncryptionContext ctx;
    uint8_t key[32];
    for (int i = 0; i < 32; i++) key[i] = (uint8_t)(i + 1);
    assert(init_aes_key_schedule(&ctx.key_schedule, key) == 0);
    for (int i = 0; i < 16; i++) ctx.iv[i] = (uint8_t)(0xA1 + i);
    ctx.mode = 1;
    
    uint8_t ciphertext[16];
    for (int i = 0; i < 16; i++) ciphertext[i] = 0xFF;
    
    DataBuffer buffer;
    buffer.data = malloc(16);
    memcpy(buffer.data, ciphertext, 16);
    buffer.length = 16;
    
    lc_error_t res = decrypt_data(&ctx, &buffer);
    assert(res == LC_PADDING_ERROR);
    
    free(buffer.data);
    cleanup_key_schedule(&ctx.key_schedule);
}

int main(void) {
    test_empty_input();
    test_single_block_encryption();
    test_partial_block_padding();
    test_invalid_padding_decryption();
    printf("All unit tests passed.\n");
    return 0;
}

#endif  /* UNIT_TESTS */

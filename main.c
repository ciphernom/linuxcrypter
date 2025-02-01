#include "linuxcrypter.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*------------------------------------------------------------
    File I/O Helper Functions
--------------------------------------------------------------*/
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

/*------------------------------------------------------------
    Usage Message
--------------------------------------------------------------*/
static void usage(const char *progname) {
    printf("Usage:\n");
    printf("  %s -e <input_file> <output_file>  (encryption)\n", progname);
    printf("  %s -d <input_file> <output_file>  (decryption)\n", progname);
}

/*------------------------------------------------------------
    Main Application Entry Point
--------------------------------------------------------------*/
#ifndef UNIT_TESTS
int main(int argc, char *argv[]) {
    if (argc != 4) {
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
    
    size_t file_length;
    uint8_t *file_data = read_file(argv[2], &file_length);
    if (!file_data) {
        fprintf(stderr, "Error reading input file.\n");
        return EXIT_FAILURE;
    }
    
    /*------------------------------------------------------------
        For demonstration purposes the EncryptionContext is
        initialized with a dummy key and IV. In production these
        must be securely generated.
    --------------------------------------------------------------*/
    EncryptionContext ctx;
    for (int i = 0; i < 32; i++) {
        ctx.key[i] = (uint8_t)(i + 1);
    }
    for (int i = 0; i < 16; i++) {
        ctx.iv[i] = (uint8_t)(0xA1 + i);
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
            free(file_data);
            return EXIT_FAILURE;
        }
    } else if (do_decrypt) {
        result = decrypt_data(&ctx, &buffer);
        if (result != LC_SUCCESS) {
            fprintf(stderr, "Decryption failed with error code: %d\n", result);
            free(file_data);
            return EXIT_FAILURE;
        }
    }
    
    if (write_file(argv[3], buffer.data, buffer.length) != 0) {
        fprintf(stderr, "Error writing output file.\n");
        free(file_data);
        return EXIT_FAILURE;
    }
    
    free(file_data);
    printf("%sion completed successfully.\n", do_encrypt ? "Encrypt" : "Decrypt");
    return EXIT_SUCCESS;
}

#else  /* UNIT_TESTS defined */

/*------------------------------------------------------------
    Unit Tests
--------------------------------------------------------------
    Tests include:
      - empty_input: empty input produces one padded block then decrypts to empty.
      - single_block_encryption: 16-byte input yields 16 bytes output.
      - partial_block_padding: input not a multiple of 16 bytes is padded correctly.
      - invalid_padding_decryption: corrupted ciphertext triggers padding error.
--------------------------------------------------------------*/
#include <assert.h>

static void test_empty_input(void) {
    EncryptionContext ctx;
    for (int i = 0; i < 32; i++) ctx.key[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 16; i++) ctx.iv[i] = (uint8_t)(0xA1 + i);
    ctx.mode = 1;
    
    DataBuffer buffer;
    buffer.data = malloc(16);
    buffer.length = 0;
    
    lc_error_t res = encrypt_data(&ctx, &buffer);
    assert(res == LC_SUCCESS);
    /* Even an empty input produces one block with full (16-byte) padding */
    assert(buffer.length == 16);
    
    res = decrypt_data(&ctx, &buffer);
    assert(res == LC_SUCCESS);
    assert(buffer.length == 0);
    free(buffer.data);
}

static void test_single_block_encryption(void) {
    EncryptionContext ctx;
    for (int i = 0; i < 32; i++) ctx.key[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 16; i++) ctx.iv[i] = (uint8_t)(0xA1 + i);
    ctx.mode = 1;
    
    uint8_t plaintext[16];
    for (int i = 0; i < 16; i++) {
        plaintext[i] = (uint8_t)i;
    }
    DataBuffer buffer;
    buffer.data = malloc(32);  // allocate 32 bytes for two blocks
    memcpy(buffer.data, plaintext, 16);
    buffer.length = 16;
    
    lc_error_t res = encrypt_data(&ctx, &buffer);
    assert(res == LC_SUCCESS);
    /* With PKCS#7 padding, a full 16-byte block produces an extra block of padding */
    assert(buffer.length == 32);
    
    res = decrypt_data(&ctx, &buffer);
    assert(res == LC_SUCCESS);
    /* After decryption the extra padding is removed, so we get back the original 16 bytes */
    assert(buffer.length == 16);
    assert(memcmp(buffer.data, plaintext, 16) == 0);
    free(buffer.data);
}


static void test_partial_block_padding(void) {
    EncryptionContext ctx;
    for (int i = 0; i < 32; i++) ctx.key[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 16; i++) ctx.iv[i] = (uint8_t)(0xA1 + i);
    ctx.mode = 1;
    
    /* 20 bytes input: one full block (16 bytes) + 4 bytes partial */
    uint8_t plaintext[20];
    for (int i = 0; i < 20; i++) {
        plaintext[i] = (uint8_t)i;
    }
    DataBuffer buffer;
    /* Allocate 32 bytes for two blocks */
    buffer.data = malloc(32);
    memcpy(buffer.data, plaintext, 20);
    buffer.length = 20;
    
    lc_error_t res = encrypt_data(&ctx, &buffer);
    assert(res == LC_SUCCESS);
    /* After padding, length must be 32 bytes */
    assert(buffer.length == 32);
    
    res = decrypt_data(&ctx, &buffer);
    assert(res == LC_SUCCESS);
    assert(buffer.length == 20);
    assert(memcmp(buffer.data, plaintext, 20) == 0);
    free(buffer.data);
}

static void test_invalid_padding_decryption(void) {
    EncryptionContext ctx;
    for (int i = 0; i < 32; i++) ctx.key[i] = (uint8_t)(i + 1);
    for (int i = 0; i < 16; i++) ctx.iv[i] = (uint8_t)(0xA1 + i);
    ctx.mode = 1;
    
    /* Create a block with invalid padding */
    uint8_t ciphertext[16];
    for (int i = 0; i < 16; i++) {
        ciphertext[i] = 0xFF;
    }
    DataBuffer buffer;
    buffer.data = malloc(16);
    memcpy(buffer.data, ciphertext, 16);
    buffer.length = 16;
    
    lc_error_t res = decrypt_data(&ctx, &buffer);
    assert(res == LC_PADDING_ERROR);
    free(buffer.data);
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

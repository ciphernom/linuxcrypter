/*============================================================*/
#ifndef LINUXCRYPTER_H
#define LINUXCRYPTER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <immintrin.h>  // For SIMD operations

/*------------------------------------------------------------
    LinuxCrypter v1.0.0
    Description: A high performance encryption/decryption tool for Linux.
    Designed for modern hardware using SIMD and inline assembly.
--------------------------------------------------------------*/

/* Error Codes */
typedef enum {
    LC_SUCCESS = 0,
    LC_INVALID_KEY = -1,
    LC_BUFFER_OVERFLOW = -2,
    LC_PADDING_ERROR = -3,
    LC_MEMORY_ERROR = -4,
    LC_GENERAL_ERROR = -5
} lc_error_t;

/*------------------------------------------------------------
    Data Structures
--------------------------------------------------------------*/

/**
 * EncryptionContext
 *
 * Holds all parameters necessary for encryption/decryption.
 * - key (uint8_t[32]): 256-bit encryption key for AES-256 or similar.
 * - iv (uint8_t[16]): Initialization vector for block modes.
 * - mode (int): Mode of operation (1 for CBC, 2 for CTR).
 *
 * Constraints:
 *  - Key and IV must be provided and correctly aligned.
 */
typedef struct {
    uint8_t key[32] __attribute__((aligned(16)));
    uint8_t iv[16] __attribute__((aligned(16)));
    int mode;   /* 1 for CBC, 2 for CTR */
} EncryptionContext;

/**
 * DataBuffer
 *
 * Generic buffer for passing plaintext or ciphertext.
 * - data (uint8_t *): Pointer to input or output data.
 * - length (size_t): Length of the data in bytes.
 *
 * Constraints:
 *  - Pointer must refer to allocated memory with proper alignment.
 */
typedef struct {
    uint8_t *data;
    size_t length;
} DataBuffer;

/*------------------------------------------------------------
    Function Prototypes
--------------------------------------------------------------*/

/* Encrypts data in-place using the provided EncryptionContext.
   Applies PKCS#7 padding to the final block if necessary. */
lc_error_t encrypt_data(EncryptionContext *ctx, DataBuffer *buffer);

/* Decrypts data in-place using the provided EncryptionContext.
   Verifies and removes PKCS#7 padding upon completion. */
lc_error_t decrypt_data(EncryptionContext *ctx, DataBuffer *buffer);

#endif // LINUXCRYPTER_H

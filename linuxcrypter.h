#ifndef LINUXCRYPTER_H
#define LINUXCRYPTER_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <immintrin.h>
#include "crypto_utils.h"  // Include this to get AESKeySchedule definition

/* Error Codes */
typedef enum {
    LC_SUCCESS = 0,
    LC_INVALID_KEY = -1,
    LC_BUFFER_OVERFLOW = -2,
    LC_PADDING_ERROR = -3,
    LC_MEMORY_ERROR = -4,
    LC_GENERAL_ERROR = -5,
    LC_KEY_SCHEDULE_ERROR = -6
} lc_error_t;

/**
 * EncryptionContext
 *
 * Holds all parameters necessary for encryption/decryption.
 * - key_schedule: Expanded AES-256 key schedule
 * - iv: 128-bit initialization vector for block modes
 * - mode: Mode of operation (1 for CBC, 2 for CTR)
 */
typedef struct {
    AESKeySchedule key_schedule;
    uint8_t iv[16] __attribute__((aligned(16)));
    int mode;   /* 1 for CBC, 2 for CTR */
} EncryptionContext;

/**
 * DataBuffer
 *
 * Generic buffer for passing plaintext or ciphertext.
 */
typedef struct {
    uint8_t *data;
    size_t length;
} DataBuffer;

/* Function Prototypes */
lc_error_t encrypt_data(EncryptionContext *ctx, DataBuffer *buffer);
lc_error_t decrypt_data(EncryptionContext *ctx, DataBuffer *buffer);

#endif // LINUXCRYPTER_H

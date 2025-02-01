#include "linuxcrypter.h"
#include "crypto_utils.h"
#include <errno.h>
#include <string.h>

/*------------------------------------------------------------
    BSS Section
    temp_buffer:
      Size: 16 bytes (BLOCK_SIZE)
      Align: 16 bytes
      Purpose: Temporary workspace for handling the final block.
--------------------------------------------------------------*/
static uint8_t temp_buffer[16] __attribute__((aligned(16)));

/**
 * encrypt_data
 *
 * Encrypts input data using the provided EncryptionContext.
 * The data is processed in 16-byte blocks using SIMD instructions.
 * This implementation uses CBC or CTR mode as selected by ctx->mode.
 *
 * PKCS#7 padding is always applied by adding an extra block:
 *   - If the plaintext is not a multiple of 16 bytes, the final block is
 *     padded with (16 - (plaintext_length mod 16)) bytes.
 *   - If the plaintext is an exact multiple of 16 bytes (or is empty),
 *     a full block of padding (16 bytes) is appended.
 *
 * Steps:
 *  initialization:
 *      - Validate that EncryptionContext and DataBuffer are properly initialized.
 *      - Load IV into a SIMD register (prev_cipher for CBC, counter for CTR).
 *  main_loop:
 *      - For each full 16-byte block, load data into a SIMD register.
 *      - For CBC mode:
 *            XOR the plaintext block with the previous ciphertext (or IV),
 *            encrypt using block_encrypt(), then update prev_cipher.
 *        - For CTR mode:
 *            Generate keystream by encrypting the counter, XOR with plaintext,
 *            and then increment the counter.
 *  cleanup:
 *      - Always append a final block with PKCS#7 padding.
 *  Preconditions:
 *      - EncryptionContext must be initialized with a valid key and IV.
 *      - DataBuffer->data must point to allocated memory.
 *  Postconditions:
 *      - Encrypted data is written in-place, and buffer->length is updated.
 *
 * @param ctx      Pointer to an initialized EncryptionContext.
 * @param buffer   Pointer to the DataBuffer containing plaintext.
 * @return         lc_error_t status.
 */
lc_error_t encrypt_data(EncryptionContext *ctx, DataBuffer *buffer) {
    if (!ctx || !buffer || !buffer->data) {
        return LC_GENERAL_ERROR;
    }
    
    size_t input_len = buffer->length;
    size_t num_full_blocks = input_len / 16;
    size_t remaining = input_len % 16;

    __m128i prev_cipher;  /* For CBC mode */
    __m128i counter;      /* For CTR mode */
    
    if (ctx->mode == 1) {
        /* CBC Mode: initial previous ciphertext is the IV */
        prev_cipher = _mm_load_si128((const __m128i*)ctx->iv);
    } else if (ctx->mode == 2) {
        /* CTR Mode: counter is initialized to IV */
        counter = _mm_load_si128((const __m128i*)ctx->iv);
    } else {
        return LC_GENERAL_ERROR;
    }
    
    uint8_t *in_ptr = buffer->data;
    /* Process all full 16-byte blocks */
    for (size_t i = 0; i < num_full_blocks; i++) {
        __m128i block = _mm_loadu_si128((const __m128i*)in_ptr);
        
        if (ctx->mode == 1) {
            /* CBC Mode: XOR plaintext block with previous ciphertext (or IV) */
            block = _mm_xor_si128(block, prev_cipher);
            __m128i enc_block = block_encrypt(block, ctx->key);
            prev_cipher = enc_block;
            _mm_storeu_si128((__m128i*)in_ptr, enc_block);
        } else {  /* CTR mode */
            __m128i keystream = block_encrypt(counter, ctx->key);
            __m128i enc_block = _mm_xor_si128(block, keystream);
            _mm_storeu_si128((__m128i*)in_ptr, enc_block);
            /* Increment the counter (here, simply increment the lower 64 bits) */
            uint64_t *ctr_ptr = (uint64_t*)&counter;
            ctr_ptr[0] = ctr_ptr[0] + 1;
        }
        in_ptr += 16;
    }
    
    /* Always add a final block with PKCS#7 padding.
       If 'remaining' is nonzero, copy the partial block into temp_buffer.
       Otherwise (or in any case) pad the final block with the value:
         pad_len = (remaining > 0) ? (16 - remaining) : 16.
    */
    memset(temp_buffer, 0, 16);
    if (remaining) {
        memcpy(temp_buffer, in_ptr, remaining);
    }
    uint8_t pad_len = (remaining > 0) ? (16 - remaining) : 16;
    for (int j = remaining; j < 16; j++) {
        temp_buffer[j] = pad_len;
    }
    
    __m128i block = _mm_load_si128((const __m128i*)temp_buffer);
    if (ctx->mode == 1) {
        block = _mm_xor_si128(block, prev_cipher);
        __m128i enc_block = block_encrypt(block, ctx->key);
        _mm_storeu_si128((__m128i*)in_ptr, enc_block);
    } else {  /* CTR mode */
        __m128i keystream = block_encrypt(counter, ctx->key);
        __m128i enc_block = _mm_xor_si128(block, keystream);
        _mm_storeu_si128((__m128i*)in_ptr, enc_block);
    }
    /* Update buffer length to reflect all blocks (including the padding block) */
    buffer->length = (num_full_blocks + 1) * 16;
    return LC_SUCCESS;
}

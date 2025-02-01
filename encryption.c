#include "linuxcrypter.h"
#include "crypto_utils.h"
#include <errno.h>
#include <string.h>

/* Temporary buffer for handling the final block */
static uint8_t temp_buffer[16] __attribute__((aligned(16)));

lc_error_t encrypt_data(EncryptionContext *ctx, DataBuffer *buffer) {
    if (!ctx || !buffer || !buffer->data) {
        return LC_GENERAL_ERROR;
    }
    
    size_t input_len = buffer->length;
    size_t num_full_blocks = input_len / 16;
    size_t remaining = input_len % 16;

    __m128i prev_cipher = _mm_setzero_si128();  /* For CBC mode */
    __m128i counter = _mm_setzero_si128();      /* For CTR mode */
    
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
            /* CBC Mode */
            block = _mm_xor_si128(block, prev_cipher);
            __m128i enc_block = block_encrypt(block, &ctx->key_schedule);
            prev_cipher = enc_block;
            _mm_storeu_si128((__m128i*)in_ptr, enc_block);
        } else {  /* CTR mode */
            __m128i keystream = block_encrypt(counter, &ctx->key_schedule);
            __m128i enc_block = _mm_xor_si128(block, keystream);
            _mm_storeu_si128((__m128i*)in_ptr, enc_block);
            /* Increment counter */
            uint64_t *ctr_ptr = (uint64_t*)&counter;
            ctr_ptr[0] = ctr_ptr[0] + 1;
        }
        in_ptr += 16;
    }
    
    /* Handle final block with PKCS#7 padding */
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
        __m128i enc_block = block_encrypt(block, &ctx->key_schedule);
        _mm_storeu_si128((__m128i*)in_ptr, enc_block);
    } else {  /* CTR mode */
        __m128i keystream = block_encrypt(counter, &ctx->key_schedule);
        __m128i enc_block = _mm_xor_si128(block, keystream);
        _mm_storeu_si128((__m128i*)in_ptr, enc_block);
    }
    
    /* Update buffer length to include padding block */
    buffer->length = (num_full_blocks + 1) * 16;
    return LC_SUCCESS;
}

#include "crypto_utils.h"

/*------------------------------------------------------------
    Data Section - Constants (read-only)
    ENCRYPT_CONST: 16-byte constant vector used for mixing.
--------------------------------------------------------------*/
static const uint8_t ENCRYPT_CONST[16] __attribute__((aligned(16))) = {
    0x0F, 0x0F, 0x0F, 0x0F,
    0x0F, 0x0F, 0x0F, 0x0F,
    0x0F, 0x0F, 0x0F, 0x0F,
    0x0F, 0x0F, 0x0F, 0x0F
};

/**
 * block_encrypt
 *
 * See documentation in crypto_utils.h.
 *
 * This function uses inline assembly to perform the following:
 *   1. Load the plaintext block and key block into xmm registers.
 *   2. XOR the plaintext with the key.
 *   3. Add the constant vector.
 *   4. Return the resulting ciphertext block.
 *
 * Registers used:
 *   - xmm0 through xmm3 are used. (xmm0-xmm7 must be preserved around calls.)
 *
 * Note: rdi/rsi and rcx are used by the C calling convention to pass pointers
 * and loop counters; our inline assembly does not alter them.
 */
__m128i block_encrypt(__m128i block, const uint8_t *key) {
    __m128i key_block = _mm_load_si128((const __m128i*)key);
    __m128i const_vec = _mm_load_si128((const __m128i*)ENCRYPT_CONST);
    __m128i out;
    asm volatile(
        "movdqa %[blk], %%xmm0\n\t"      /* xmm0 = block */
        "movdqa %[kblk], %%xmm1\n\t"       /* xmm1 = key_block */
        "pxor %%xmm1, %%xmm0\n\t"          /* xmm0 = block XOR key_block */
        "movdqa %%xmm0, %%xmm2\n\t"        /* xmm2 = copy of result */
        "movdqa %[cvec], %%xmm3\n\t"       /* xmm3 = constant vector */
        "paddb %%xmm3, %%xmm2\n\t"         /* xmm2 = result + constant (mod 256) */
        "movdqa %%xmm2, %[out]\n\t"        /* store result */
        : [out] "=m" (out)
        : [blk] "m" (block), [kblk] "m" (key_block), [cvec] "m" (const_vec)
        : "xmm0", "xmm1", "xmm2", "xmm3"
    );
    return out;
}

/**
 * block_decrypt
 *
 * See documentation in crypto_utils.h.
 *
 * This function reverses the encryption process:
 *   1. Subtract the constant vector from the ciphertext.
 *   2. XOR the result with the key block.
 *
 * Inline assembly is used similarly to block_encrypt.
 */
__m128i block_decrypt(__m128i block, const uint8_t *key) {
    __m128i key_block = _mm_load_si128((const __m128i*)key);
    __m128i const_vec = _mm_load_si128((const __m128i*)ENCRYPT_CONST);
    __m128i out;
    asm volatile(
        "movdqa %[blk], %%xmm0\n\t"      /* xmm0 = ciphertext block */
        "movdqa %[cvec], %%xmm1\n\t"       /* xmm1 = constant vector */
        "psubb %%xmm1, %%xmm0\n\t"         /* xmm0 = block - constant (mod 256) */
        "movdqa %[kblk], %%xmm2\n\t"       /* xmm2 = key block */
        "pxor %%xmm2, %%xmm0\n\t"          /* xmm0 = result XOR key_block */
        "movdqa %%xmm0, %[out]\n\t"        /* store result */
        : [out] "=m" (out)
        : [blk] "m" (block), [kblk] "m" (key_block), [cvec] "m" (const_vec)
        : "xmm0", "xmm1", "xmm2"
    );
    return out;
}

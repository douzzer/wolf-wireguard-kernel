#include "wolfcrypto_shim.h"
#include <crypto/scatterwalk.h>

int curve25519_generate_public(
    uint8_t pub[static CURVE25519_KEY_SIZE],
    const uint8_t secret[static CURVE25519_KEY_SIZE])
{
    /* pubkey_main() calls curve25519_generate_public() with pub == secret,
     * which doesn't work for wc_curve25519_make_pub().
     */
    uint8_t secret_copy[CURVE25519_KEY_SIZE];
    XMEMCPY(secret_copy, secret, CURVE25519_KEY_SIZE);
    return !DBG_PRNT_NZ(wc_curve25519_make_pub(CURVE25519_KEY_SIZE, pub, CURVE25519_KEY_SIZE, secret_copy));
}

int curve25519_generate_secret(u8 secret[CURVE25519_KEY_SIZE]) {
    WC_RNG *gRng = wc_rng_new(NULL /* nonce */, 0 /* nonceSz */, NULL /*heap */);
    if (gRng) {
        (void)DBG_PRNT_NZ(wc_curve25519_make_priv(gRng, (int)CURVE25519_KEY_SIZE, (byte *)secret));
        wc_rng_free(gRng);
        return 0;
    } else
        return -ENOMEM;
}

int blake2s(byte *out, const void *in, const void *key, const byte outlen,
            const word32 inlen, byte keylen)
{
    Blake2s state;

    if ((in == NULL) || (out == NULL))
        return -1;

    if (DBG_PRNT_NZ(wc_InitBlake2s_WithKey(&state, (word32)outlen, (const byte *)key, (word32)keylen)) < 0)
        return -1;
    if (DBG_PRNT_NZ(wc_Blake2sUpdate(&state, (byte *)in, inlen)) < 0)
        return -1;
    return DBG_PRNT_NZ(wc_Blake2sFinal(&state, out, (word32)outlen));
}

void blake2s_hmac(byte *out, const byte *in, const byte *key, size_t outlen, size_t inlen, size_t keylen) {
    Blake2s state;
    word32 x_key[BLAKE2S_BLOCK_SIZE / sizeof(word32)];
    word32 i_hash[BLAKE2S_HASH_SIZE / sizeof(word32)];
    int i;

    if (outlen != BLAKE2S_HASH_SIZE)
        return;

    if (keylen > BLAKE2S_BLOCK_SIZE) {
        DBG_PRNT_NZ(wc_InitBlake2s(&state, BLAKE2S_HASH_SIZE));
        DBG_PRNT_NZ(wc_Blake2sUpdate(&state, key, keylen));
        DBG_PRNT_NZ(wc_Blake2sFinal(&state, (byte *)x_key, 0));
    } else {
        XMEMCPY(x_key, key, keylen);
        XMEMSET((byte *)x_key + keylen, 0, BLAKE2S_BLOCK_SIZE - keylen);
    }

    for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
        ((byte *)x_key)[i] ^= 0x36;

    DBG_PRNT_NZ(wc_InitBlake2s(&state, BLAKE2S_HASH_SIZE));
    DBG_PRNT_NZ(wc_Blake2sUpdate(&state, (byte *)x_key, BLAKE2S_BLOCK_SIZE));
    DBG_PRNT_NZ(wc_Blake2sUpdate(&state, in, inlen));
    DBG_PRNT_NZ(wc_Blake2sFinal(&state, (byte *)i_hash, 0));

    for (i = 0; i < BLAKE2S_BLOCK_SIZE; ++i)
        ((byte *)x_key)[i] ^= 0x5c ^ 0x36;

    DBG_PRNT_NZ(wc_InitBlake2s(&state, BLAKE2S_HASH_SIZE));
    DBG_PRNT_NZ(wc_Blake2sUpdate(&state, (byte *)x_key, BLAKE2S_BLOCK_SIZE));
    DBG_PRNT_NZ(wc_Blake2sUpdate(&state, (byte *)i_hash, BLAKE2S_HASH_SIZE));
    DBG_PRNT_NZ(wc_Blake2sFinal(&state, (byte *)i_hash, 0));

    XMEMCPY(out, i_hash, BLAKE2S_HASH_SIZE);
    XMEMSET(x_key, 0, BLAKE2S_BLOCK_SIZE);
    XMEMSET(i_hash, 0, BLAKE2S_HASH_SIZE);
}

void blake2s256_hmac(byte *out, const byte *in, const byte *key, size_t inlen, size_t keylen) {
  blake2s_hmac(out, in, key, BLAKE2S_HASH_SIZE, inlen, keylen);
}

static bool chacha20poly1305_crypt_sg_inplace(struct scatterlist *src,
				       const size_t src_len,
				       const u8 *ad, const size_t ad_len,
				       const u64 nonce,
				       const u8 key[CHACHA20POLY1305_KEY_SIZE],
				       int isEncrypt)
{
    int ret = -1;
    struct sg_mapping_iter miter;
    unsigned int flags;
    int sl;
    ChaChaPoly_Aead *aead = (ChaChaPoly_Aead *)XMALLOC(sizeof *aead, NULL, DYNAMIC_TYPE_TMP_BUFFER);

    if (WARN_ON(src_len > INT_MAX)) {
        ret = BAD_FUNC_ARG;
        goto out;
    }

    {
        byte IV[CHACHA20_POLY1305_AEAD_IV_SIZE] = {};
        memcpy(IV + 4, (byte *)&nonce, sizeof nonce);
        if (WARN_ON(wc_ChaCha20Poly1305_Init(aead, key, IV, isEncrypt) < 0))
            goto out;
        XMEMSET(IV, 0, sizeof IV);
    }

    flags = SG_MITER_TO_SG;
    if (!preemptible())
        flags |= SG_MITER_ATOMIC;

    sg_miter_start(&miter, src, sg_nents(src), flags);

    for (sl = src_len; sl > 0 && sg_miter_next(&miter); sl -= miter.length) {
        size_t length = min_t(size_t, sl, miter.length);

        if (! isEncrypt) {
            if ((ret = wc_Poly1305Update(&aead->poly, miter.addr, length)) < 0)
                goto out;
        }

        if ((ret = wc_Chacha_Process(&aead->chacha, miter.addr, miter.addr, length)) < 0)
            goto out;

        if (isEncrypt) {
            if ((ret = wc_Poly1305Update(&aead->poly, miter.addr, length)) < 0)
                goto out;
        }
    }

    if (aead->poly.leftover) {
        if ((ret = wc_Poly1305_Pad(&aead->poly, (word32)aead->poly.leftover)) < 0)
            goto out;
    }

    if ((ret = wc_Poly1305_EncodeSizes(&aead->poly, ad_len, src_len)) < 0)
        goto out;

    /* the remaining length (sl) really will be conditionally negative after
     * iteration -- this is Jason Donenfeld's algorithm from
     * chacha20poly1305_crypt_sg_inplace() in Linux
     * lib/crypto/chacha20poly1305.c.
     */
    if (sl <= -POLY1305_DIGEST_SIZE) {
        if (isEncrypt) {
            if ((ret = wc_Poly1305Final(&aead->poly, miter.addr + miter.length + sl)) < 0)
                goto out;
        } else {
            byte outAuthTag[POLY1305_DIGEST_SIZE];

            if ((ret = wc_Poly1305Final(&aead->poly, outAuthTag)) < 0)
                goto out;

            if (ConstantCompare(outAuthTag, miter.addr + miter.length + sl, POLY1305_DIGEST_SIZE) != 0) {
                ret = MAC_CMP_FAILED_E;
                goto out;
            }
        }
    }

    sg_miter_stop(&miter);

    if (sl > -POLY1305_DIGEST_SIZE) {
        byte outAuthTag[POLY1305_DIGEST_SIZE];
        wc_Poly1305Final(&aead->poly, outAuthTag);
        if (isEncrypt) {
            scatterwalk_map_and_copy(outAuthTag, src, src_len,
                                     sizeof outAuthTag, isEncrypt);
        } else {
            byte refAuthTag[POLY1305_DIGEST_SIZE];
            scatterwalk_map_and_copy(refAuthTag, src, src_len,
                                     sizeof outAuthTag, isEncrypt);
            if (ConstantCompare(outAuthTag, refAuthTag, POLY1305_DIGEST_SIZE) != 0) {
                ret = MAC_CMP_FAILED_E;
                goto out;
            }
        }
    }

    ret = 0;

  out:

    if (aead) {
        XMEMSET(&aead, 0, sizeof aead);
        XFREE(aead, NULL, DYNAMIC_TYPE_TMP_BUFFER);
    }

    (void)DBG_PRNT_NZ(ret);

    return ret == 0;
}

bool chacha20poly1305_encrypt_sg_inplace(struct scatterlist *src, size_t src_len,
					 const u8 *ad, const size_t ad_len,
					 const u64 nonce,
					 const u8 key[CHACHA20POLY1305_KEY_SIZE],
					 simd_context_t *simd_context)
{
	(void)simd_context;
	return chacha20poly1305_crypt_sg_inplace(src, src_len, ad, ad_len,
						 nonce, key, 1);
}

bool chacha20poly1305_decrypt_sg_inplace(struct scatterlist *src, size_t src_len,
					 const u8 *ad, const size_t ad_len,
					 const u64 nonce,
					 const u8 key[CHACHA20POLY1305_KEY_SIZE],
					 simd_context_t *simd_context)
{
	(void)simd_context;

	if (unlikely(src_len < POLY1305_DIGEST_SIZE))
		return false;

	return chacha20poly1305_crypt_sg_inplace(src,
						 src_len - POLY1305_DIGEST_SIZE,
						 ad, ad_len, nonce, key, 0);
}

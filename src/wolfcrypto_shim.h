#ifndef WOLFCRYPTO_SHIM_H
#define WOLFCRYPTO_SHIM_H

#include <wolfssl/options.h>
#ifndef WOLFSSL_LINUXKM
#error libwolfssl configured without --enable-linuxkm
#endif
#ifndef HAVE_CURVE25519
#error libwolfssl missing HAVE_CURVE25519
#endif
#ifndef HAVE_BLAKE2S
#error libwolfssl missing HAVE_BLAKE2S
#endif
#ifndef HAVE_CHACHA
#error libwolfssl missing HAVE_CHACHA
#endif
#ifndef HAVE_POLY1305
#error libwolfssl missing HAVE_POLY1305
#endif

#undef SHA256_BLOCK_SIZE
#undef SHA256_DIGEST_SIZE
#undef SHA224_BLOCK_SIZE
#undef SHA224_DIGEST_SIZE
#undef CURVE25519_KEYSIZE

#include <wolfssl/wolfcrypt/wc_port.h>
#include <wolfssl/wolfcrypt/error-crypt.h>
#define WOLFSSL_MISC_INCLUDED
#undef min
#undef max
#include <wolfcrypt/src/misc.c>

#include <wolfssl/wolfcrypt/curve25519.h>
#define CURVE25519_KEY_SIZE CURVE25519_KEYSIZE

#include <wolfssl/wolfcrypt/chacha.h>

#include <wolfssl/wolfcrypt/poly1305.h>
#define CHACHA20POLY1305_KEY_SIZE CHACHA20_POLY1305_AEAD_KEYSIZE
#define CHACHA20POLY1305_AUTHTAG_SIZE CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE
#define XCHACHA20POLY1305_NONCE_SIZE 24 /* CHACHA20_POLY1305_AEAD_IV_SIZE * 2 */

#include <wolfssl/wolfcrypt/chacha20_poly1305.h>

#include <wolfssl/wolfcrypt/blake2.h>
#define BLAKE2S_HASH_SIZE BLAKE2S_256
#define BLAKE2S_BLOCK_SIZE 64

#include <linux/kconfig.h>
#include <linux/simd.h>
#include <linux/kernel.h>
#include <linux/scatterlist.h>

#ifdef DEBUG
#define DBG_PRNT_NZ(...) ({ int _ret = (__VA_ARGS__); if (_ret) printk(KERN_NOTICE "%s@%d: %d\n", __FILE__, __LINE__, _ret); _ret; })
#else
#define DBG_PRNT_NZ(...) (__VA_ARGS__)
#endif

struct blake2s_state {
  Blake2s blake2s;
};
#define blake2s_init(...) wc_wg_blake2s_init(__VA_ARGS__)
static void __attribute__((unused)) inline blake2s_init(struct blake2s_state *state, size_t outlen) {
  DBG_PRNT_NZ(wc_InitBlake2s(&state->blake2s, (word32)outlen));
}
#define blake2s_init_key(...) wc_wg_blake2s_init_key(__VA_ARGS__)
static void __attribute__((unused)) inline blake2s_init_key(struct blake2s_state *state, size_t outlen, const void *key,
                                                            const size_t keylen) {
  DBG_PRNT_NZ(wc_InitBlake2s_WithKey(&state->blake2s, (word32)outlen, (const byte *)key, (word32)keylen));
}
#define blake2s_update(...) wc_wg_blake2s_update(__VA_ARGS__)
static void __attribute__((unused)) inline blake2s_update(struct blake2s_state *state, const u8 *in, size_t inlen) {
  DBG_PRNT_NZ(wc_Blake2sUpdate(&state->blake2s, (const byte *)in, (word32)inlen));
}
#define blake2s_final(...) wc_wg_blake2s_final(__VA_ARGS__)
static void __attribute__((unused)) inline blake2s_final(struct blake2s_state *state, const u8 *out) {
  DBG_PRNT_NZ(wc_Blake2sFinal(&state->blake2s, (byte *)out, 0));
}

#define blake2s(...) wc_wg_simple_blake2s(__VA_ARGS__)
extern int blake2s(byte *out, const void *in, const void *key, const byte outlen,
                   const word32 inlen, byte keylen);

#define blake2s256_hmac(...) wc_wg_blake2s256_hmac(__VA_ARGS__)
extern void blake2s256_hmac(byte *out, const byte *in, const byte *key, size_t inlen, size_t keylen);

#define blake2s_hmac(...) wc_wg_blake2s_hmac(__VA_ARGS__)
extern void blake2s_hmac(byte *out, const byte *in, const byte *key, size_t outlen, size_t inlen, size_t keylen);

#define curve25519_generate_public(...) curve25519_generate_public_wolfshim(__VA_ARGS__)
extern int curve25519_generate_public(uint8_t pub[static CURVE25519_KEYSIZE], const uint8_t secret[static CURVE25519_KEYSIZE]);

#define curve25519_generate_secret(...) curve25519_generate_secret_wolfshim(__VA_ARGS__)
extern int curve25519_generate_secret(u8 secret[CURVE25519_KEY_SIZE]);

#define curve25519_clamp_secret(...) curve25519_clamp_secret_wolfshim(__VA_ARGS__)
static inline void curve25519_clamp_secret(u8 key[CURVE25519_KEY_SIZE])
{
  key[0] &= 248;
  key[CURVE25519_KEY_SIZE-1] &= 63; /* same &=127 because |=64 after */
  key[CURVE25519_KEY_SIZE-1] |= 64;
}

#define curve25519(...) curve25519_wolfshim(__VA_ARGS__)
static inline bool curve25519(uint8_t mypublic[static CURVE25519_KEY_SIZE], const uint8_t secret[static CURVE25519_KEY_SIZE], const uint8_t basepoint[static CURVE25519_KEY_SIZE]) {
  return (wc_curve25519_generic(CURVE25519_KEY_SIZE, (byte *)mypublic, CURVE25519_KEY_SIZE, (byte *)secret, CURVE25519_KEY_SIZE, (byte *)basepoint) == 0 ? true : false);
}

static __attribute__((unused)) inline void
chacha20poly1305_encrypt(u8 *dst, const u8 *src, const size_t src_len,
                         const u8 *ad, const size_t ad_len,
                         const u64 nonce,
                         const u8 key[CHACHA20POLY1305_KEY_SIZE]) {
  word64 inIV[2] = { 0, cpu_to_le64(nonce) };
    ChaChaPoly_Aead aead;

    if (DBG_PRNT_NZ(wc_ChaCha20Poly1305_Init(&aead, key, (const byte *)inIV,
						CHACHA20_POLY1305_AEAD_ENCRYPT)))
      return;

    DBG_PRNT_NZ(wc_ChaCha20Poly1305_UpdateAad(&aead, ad, (u32)ad_len));
    if (src_len)
        DBG_PRNT_NZ(wc_ChaCha20Poly1305_UpdateData(&aead, src, dst,
						      (u32)src_len));
    DBG_PRNT_NZ(wc_ChaCha20Poly1305_Final(&aead, dst + src_len));
}

static __attribute__((unused)) inline bool
chacha20poly1305_decrypt(u8 *dst, const u8 *src, const size_t src_len,
                         const u8 *ad, const size_t ad_len,
                         const u64 nonce,
                         const u8 key[CHACHA20POLY1305_KEY_SIZE]) {
  word64 inIV[2] = { 0, cpu_to_le64(nonce) };

  int ret = 0;
  ChaChaPoly_Aead aead;
  byte calculatedAuthTag[CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE] = {};

  if (DBG_PRNT_NZ
      (wc_ChaCha20Poly1305_Init(&aead, key, (const u8 *)inIV + sizeof inIV - CHACHA20_POLY1305_AEAD_IV_SIZE,
				CHACHA20_POLY1305_AEAD_DECRYPT)))
    return false;
  ret |= DBG_PRNT_NZ(wc_ChaCha20Poly1305_UpdateAad(&aead, ad, (u32)ad_len));
  if (dst)
    ret |= DBG_PRNT_NZ(wc_ChaCha20Poly1305_UpdateData(&aead, src, dst, src_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE));
  ret |= DBG_PRNT_NZ(wc_ChaCha20Poly1305_Final(&aead, calculatedAuthTag));
  ret |= DBG_PRNT_NZ(wc_ChaCha20Poly1305_CheckTag(src + src_len - CHACHA20_POLY1305_AEAD_AUTHTAG_SIZE, calculatedAuthTag));

  return ret == 0;
}

#define xchacha20poly1305_encrypt(dst, src, src_len, ad, ad_len, nonce, key) \
  DBG_PRNT_NZ(wc_XChaCha20Poly1305_Encrypt(dst, (src_len) + POLY1305_DIGEST_SIZE, src, src_len, ad, ad_len, nonce, XCHACHA20POLY1305_NONCE_SIZE, key, CHACHA20POLY1305_KEY_SIZE))
#define xchacha20poly1305_decrypt(dst, src, src_len, ad, ad_len, nonce, key) \
  (DBG_PRNT_NZ(wc_XChaCha20Poly1305_Decrypt(dst, (src_len) - POLY1305_DIGEST_SIZE, src, src_len, ad, ad_len, nonce, XCHACHA20POLY1305_NONCE_SIZE, key, CHACHA20POLY1305_KEY_SIZE)) == 0)

#define chacha20poly1305_encrypt_sg_inplace(...) \
  chacha20poly1305_encrypt_sg_inplace_wolfshim(__VA_ARGS__)
extern bool chacha20poly1305_encrypt_sg_inplace(struct scatterlist *src, size_t src_len,
					 const u8 *ad, const size_t ad_len,
					 const u64 nonce,
                                                const u8 key[CHACHA20POLY1305_KEY_SIZE],
					 simd_context_t *simd_context);

#define chacha20poly1305_decrypt_sg_inplace(...) \
  chacha20poly1305_decrypt_sg_inplace_wolfshim(__VA_ARGS__)
extern bool chacha20poly1305_decrypt_sg_inplace(struct scatterlist *src, size_t src_len,
					 const u8 *ad, const size_t ad_len,
					 const u64 nonce,
                                                const u8 key[CHACHA20POLY1305_KEY_SIZE],
					 simd_context_t *simd_context);

#endif

#ifndef GOOGLE_FUNCTIONAL_H // !GOOGLE_FUNCTIONAL_H
#define GOOGLE_FUNCTIONAL_H

#include "Log.h"

#include <openssl/ssl.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/bn.h>
#include <openssl/hkdf.h>

#include <string>
#include <string_view>
#include <vector>
#include <optional>

// Size of an RSA modulus such as an encrypted block or a signature.
#define ANDROID_PUBKEY_MODULUS_SIZE (2048 / 8)
// Size of an encoded RSA key.
#define ANDROID_PUBKEY_ENCODED_SIZE \
    (3 * sizeof(uint32_t) + 2 * ANDROID_PUBKEY_MODULUS_SIZE)
// Size of the RSA modulus in words.
#define ANDROID_PUBKEY_MODULUS_SIZE_WORDS (ANDROID_PUBKEY_MODULUS_SIZE / 4)
// This file implements encoding and decoding logic for Android's custom RSA
// public key binary format. Public keys are stored as a sequence of
// little-endian 32 bit words. Note that Android only supports little-endian
// processors, so we don't do any byte order conversions when parsing the binary
// struct.
struct RSAPublicKey
{
    // Modulus length. This must be ANDROID_PUBKEY_MODULUS_SIZE.
    uint32_t modulus_size_words;
    // Precomputed montgomery parameter: -1 / n[0] mod 2^32
    uint32_t n0inv;
    // RSA modulus as a little-endian array.
    uint8_t modulus[ANDROID_PUBKEY_MODULUS_SIZE];
    // Montgomery parameter R^2 as a little-endian array.
    uint8_t rr[ANDROID_PUBKEY_MODULUS_SIZE];
    // RSA modulus: 3 or 65537
    uint32_t exponent;
};

class Aes128Gcm
{
public:
    explicit Aes128Gcm(const uint8_t *key_material, size_t key_material_len);

    // Encrypt a block of data in |in| of length |in_len|, this consumes all data
    // in |in| and places the encrypted data in |out| if |out_len| indicates that
    // there is enough space. The data contains information needed for
    // decryption that is specific to this implementation and is therefore only
    // suitable for decryption with this class.
    // The method returns the number of bytes placed in |out| on success and a
    // negative value if an error occurs.
    std::optional<size_t> Encrypt(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);
    // Decrypt a block of data in |in| of length |in_len|, this consumes all data
    // in |in_len| bytes of data. The decrypted output is placed in the |out|
    // buffer of length |out_len|. On successful decryption the number of bytes in
    // |out| will be placed in |out_len|.
    // The method returns the number of bytes consumed from the |in| buffer. If
    // there is not enough data available in |in| the method returns zero. If
    // an error occurs the method returns a negative value.
    std::optional<size_t> Decrypt(const uint8_t *in, size_t in_len, uint8_t *out, size_t out_len);

    // Return a safe amount of buffer storage needed to encrypt |size| bytes.
    size_t EncryptedSize(size_t size);
    // Return a safe amount of buffer storage needed to decrypt |size| bytes.
    size_t DecryptedSize(size_t size);

private:
    bssl::ScopedEVP_AEAD_CTX context_;
    // Sequence numbers to use as nonces in the encryption scheme
    uint64_t dec_sequence_ = 0;
    uint64_t enc_sequence_ = 0;
};

bssl::UniquePtr<EVP_PKEY> EvpPkeyFromPEM(std::string_view pem);

bssl::UniquePtr<CRYPTO_BUFFER> BufferFromPEM(std::string_view pem);

bssl::UniquePtr<X509> GenerateX509Certificate(EVP_PKEY *pkey);

std::string EVPKeyToPEMString(EVP_PKEY *pkey);

bool AndroidPubkeyDecode(const uint8_t *key_buffer, size_t size, RSA **key);

bool AndroidPubkeyEncode(const RSA *key, uint8_t *key_buffer, size_t size);

bool CalculatePublicKey(std::string *out, RSA *private_key);

bssl::UniquePtr<EVP_PKEY> CreateRSA2048PrivateKey();

#endif // !GOOGLE_FUNCTIONAL_H
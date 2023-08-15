#include "GoogleFunctional.h"

const char kBasicConstraints[] = "critical,CA:TRUE";
const char kKeyUsage[] = "critical,keyCertSign,cRLSign,digitalSignature";
const char kSubjectKeyIdentifier[] = "hash";
constexpr int kCertLifetimeSeconds = 10 * 365 * 24 * 60 * 60;
// Size of AES-128-GCM key, in bytes
static constexpr size_t kHkdfKeyLength = 16;

Aes128Gcm::Aes128Gcm(const uint8_t *key_material, size_t key_material_len)
{
    uint8_t key[kHkdfKeyLength];
    uint8_t info[] = "adb pairing_auth aes-128-gcm key";

    if (1 != HKDF(key, sizeof(key), EVP_sha256(), key_material, key_material_len, nullptr, 0, info, sizeof(info) - 1))
    {
        LogError("Aes128Gcm -> HKDF error");
        return;
    }

    if (!EVP_AEAD_CTX_init(context_.get(), EVP_aead_aes_128_gcm(), key, sizeof(key), EVP_AEAD_DEFAULT_TAG_LENGTH, nullptr))
    {
        LogError("Aes128Gcm -> EVP_AEAD_CTX_init error");
        return;
    }
}

std::optional<size_t> Aes128Gcm::Encrypt(const uint8_t *in, size_t in_len, uint8_t *out,
                                         size_t out_len)
{
    std::vector<uint8_t> nonce(EVP_AEAD_nonce_length(EVP_AEAD_CTX_aead(context_.get())), 0);
    memcpy(nonce.data(), &enc_sequence_, sizeof(enc_sequence_));
    size_t written_sz;
    if (!EVP_AEAD_CTX_seal(context_.get(), out, &written_sz, out_len, nonce.data(), nonce.size(),
                           in, in_len, nullptr, 0))
    {
        LogFailed("Aes128Gcm: failed to encrypt (in_len=%zd, out_len=%zd, out_len_needed=%zd)", in_len, out_len, EncryptedSize(in_len));
        return std::nullopt;
    }

    ++enc_sequence_;
    return written_sz;
}

std::optional<size_t> Aes128Gcm::Decrypt(const uint8_t *in, size_t in_len, uint8_t *out,
                                         size_t out_len)
{
    std::vector<uint8_t> nonce(EVP_AEAD_nonce_length(EVP_AEAD_CTX_aead(context_.get())), 0);
    memcpy(nonce.data(), &dec_sequence_, sizeof(dec_sequence_));
    size_t written_sz;
    if (!EVP_AEAD_CTX_open(context_.get(), out, &written_sz, out_len, nonce.data(), nonce.size(),
                           in, in_len, nullptr, 0))
    {
        LogFailed("Aes128Gcm: failed to decrypt (in_len=%zd, out_len=%zd, out_len_needed=%zd)", in_len, out_len, DecryptedSize(in_len));
        return std::nullopt;
    }

    ++dec_sequence_;
    return written_sz;
}

size_t Aes128Gcm::EncryptedSize(size_t size)
{
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/aead.h.html#EVP_AEAD_CTX_seal
    return size + EVP_AEAD_max_overhead(EVP_AEAD_CTX_aead(context_.get()));
}

size_t Aes128Gcm::DecryptedSize(size_t size)
{
    // https://commondatastorage.googleapis.com/chromium-boringssl-docs/aead.h.html#EVP_AEAD_CTX_open
    return size;
}

bssl::UniquePtr<EVP_PKEY> EvpPkeyFromPEM(std::string_view pem)
{
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem.data(), pem.size()));

    return bssl::UniquePtr<EVP_PKEY>(PEM_read_bio_PrivateKey(bio.get(), nullptr, nullptr, nullptr));
}

bssl::UniquePtr<CRYPTO_BUFFER> BufferFromPEM(std::string_view pem)
{
    bssl::UniquePtr<BIO> bio(BIO_new_mem_buf(pem.data(), pem.size()));
    char *name = nullptr;
    char *header = nullptr;
    uint8_t *data = nullptr;
    long data_len = 0;

    if (!PEM_read_bio(bio.get(), &name, &header, &data, &data_len))
    {
        LogFailed("BufferFromPEM: failed to read certificate");
        return nullptr;
    }
    OPENSSL_free(name);
    OPENSSL_free(header);

    auto ret = bssl::UniquePtr<CRYPTO_BUFFER>(CRYPTO_BUFFER_new(data, data_len, nullptr));
    OPENSSL_free(data);
    return ret;
}

bssl::UniquePtr<X509> GenerateX509Certificate(EVP_PKEY *pkey)
{
    auto add_ext = [](X509 *cert, int nid, const char *value) -> bool
    {
        size_t len = strlen(value) + 1;
        std::vector<char> mutableValue(value, value + len);
        X509V3_CTX context;

        X509V3_set_ctx_nodb(&context);

        X509V3_set_ctx(&context, cert, cert, nullptr, nullptr, 0);
        X509_EXTENSION *ex = X509V3_EXT_nconf_nid(nullptr, &context, nid, mutableValue.data());
        if (!ex)
        {
            return false;
        }

        X509_add_ext(cert, ex, -1);
        X509_EXTENSION_free(ex);
        return true;
    };

    bssl::UniquePtr<X509> x509(X509_new());
    if (!x509)
    {
        LogFailed("X509_new: unable to allocate x509 container");
        return nullptr;
    }
    X509_set_version(x509.get(), 2);

    ASN1_INTEGER_set(X509_get_serialNumber(x509.get()), 1);
    X509_gmtime_adj(X509_get_notBefore(x509.get()), 0);
    X509_gmtime_adj(X509_get_notAfter(x509.get()), kCertLifetimeSeconds);

    if (!X509_set_pubkey(x509.get(), pkey))
    {
        LogFailed("X509_set_pubkey: unable to set x509 public key");
        return nullptr;
    }

    X509_NAME *name = X509_get_subject_name(x509.get());
    if (!name)
    {
        LogFailed("X509_get_subject_name: unable to get x509 subject name");
        return nullptr;
    }
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>("US"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>("Android"), -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC,
                               reinterpret_cast<const unsigned char *>("Adb"), -1, -1, 0);
    if (!X509_set_issuer_name(x509.get(), name))
    {
        LogFailed("X509_set_issuer_name: unable to set x509 issuer name");
        return nullptr;
    }

    add_ext(x509.get(), NID_basic_constraints, kBasicConstraints);
    add_ext(x509.get(), NID_key_usage, kKeyUsage);
    add_ext(x509.get(), NID_subject_key_identifier, kSubjectKeyIdentifier);

    int bytes = X509_sign(x509.get(), pkey, EVP_sha256());
    if (bytes <= 0)
    {
        LogFailed("X509_sign: unable to sign x509 certificate");
        return nullptr;
    }

    return x509;
}

std::string EVPKeyToPEMString(EVP_PKEY *pkey)
{
    bssl::UniquePtr<BIO> bio(BIO_new(BIO_s_mem()));
    int rc = PEM_write_bio_PKCS8PrivateKey(bio.get(), pkey, nullptr, nullptr, 0, nullptr, nullptr);
    if (rc != 1)
    {
        LogFailed("PEM_write_bio_PKCS8PrivateKey failed");
        return "";
    }

    BUF_MEM *mem = nullptr;
    BIO_get_mem_ptr(bio.get(), &mem);
    if (!mem || !mem->data || !mem->length)
    {
        LogFailed("BIO_get_mem_ptr failed");
        return "";
    }

    return std::string(mem->data, mem->length);
}

bool AndroidPubkeyDecode(const uint8_t *key_buffer, size_t size, RSA **key)
{
    const RSAPublicKey *key_struct = (RSAPublicKey *)key_buffer;
    bool ret = false;
    RSA *new_key = RSA_new();
    BIGNUM *n = NULL;
    BIGNUM *e = NULL;
    if (!new_key)
    {
        goto cleanup;
    }
    // Check |size| is large enough and the modulus size is correct.
    if (size < sizeof(RSAPublicKey))
    {
        goto cleanup;
    }
    if (key_struct->modulus_size_words != ANDROID_PUBKEY_MODULUS_SIZE_WORDS)
    {
        goto cleanup;
    }
    // Convert the modulus to big-endian byte order as expected by BN_bin2bn.
    n = BN_le2bn(key_struct->modulus, ANDROID_PUBKEY_MODULUS_SIZE, NULL);
    if (!n)
    {
        goto cleanup;
    }
    // Read the exponent.
    e = BN_new();
    if (!e || !BN_set_word(e, key_struct->exponent))
    {
        goto cleanup;
    }
    if (!RSA_set0_key(new_key, n, e, NULL))
    {
        goto cleanup;
    }
    // RSA_set0_key takes ownership of its inputs on success.
    n = NULL;
    e = NULL;
    // Note that we don't extract the montgomery parameters n0inv and rr from
    // the RSAPublicKey structure. They assume a word size of 32 bits, but
    // BoringSSL may use a word size of 64 bits internally, so we're lacking the
    // top 32 bits of n0inv in general. For now, we just ignore the parameters
    // and have BoringSSL recompute them internally. More sophisticated logic can
    // be added here if/when we want the additional speedup from using the
    // pre-computed montgomery parameters.
    *key = new_key;
    new_key = NULL;
    ret = true;
cleanup:
    RSA_free(new_key);
    BN_free(n);
    BN_free(e);
    return ret;
}

bool AndroidPubkeyEncode(const RSA *key, uint8_t *key_buffer, size_t size)
{
    RSAPublicKey *key_struct = (RSAPublicKey *)key_buffer;
    bool ret = false;
    BN_CTX *ctx = BN_CTX_new();
    BIGNUM *r32 = BN_new();
    BIGNUM *n0inv = BN_new();
    BIGNUM *rr = BN_new();
    if (sizeof(RSAPublicKey) > size || RSA_size(key) != ANDROID_PUBKEY_MODULUS_SIZE)
    {
        goto cleanup;
    }
    // Store the modulus size.
    key_struct->modulus_size_words = ANDROID_PUBKEY_MODULUS_SIZE_WORDS;
    // Compute and store n0inv = -1 / N[0] mod 2^32.
    if (!ctx || !r32 || !n0inv || !BN_set_bit(r32, 32) || !BN_mod(n0inv, RSA_get0_n(key), r32, ctx) ||
        !BN_mod_inverse(n0inv, n0inv, r32, ctx) || !BN_sub(n0inv, r32, n0inv))
    {
        goto cleanup;
    }
    key_struct->n0inv = (uint32_t)BN_get_word(n0inv);
    // Store the modulus.
    if (!BN_bn2le_padded(key_struct->modulus, ANDROID_PUBKEY_MODULUS_SIZE, RSA_get0_n(key)))
    {
        goto cleanup;
    }
    // Compute and store rr = (2^(rsa_size)) ^ 2 mod N.
    if (!ctx || !rr || !BN_set_bit(rr, ANDROID_PUBKEY_MODULUS_SIZE * 8) ||
        !BN_mod_sqr(rr, rr, RSA_get0_n(key), ctx) ||
        !BN_bn2le_padded(key_struct->rr, ANDROID_PUBKEY_MODULUS_SIZE, rr))
    {
        goto cleanup;
    }
    // Store the exponent.
    key_struct->exponent = (uint32_t)BN_get_word(RSA_get0_e(key));
    ret = true;
cleanup:
    BN_free(rr);
    BN_free(n0inv);
    BN_free(r32);
    BN_CTX_free(ctx);
    return ret;
}

bool CalculatePublicKey(std::string *out, RSA *private_key)
{
    uint8_t binary_key_data[ANDROID_PUBKEY_ENCODED_SIZE];
    if (!AndroidPubkeyEncode(private_key, binary_key_data, sizeof(binary_key_data)))
    {
        LogFailed("AndroidPubkeyEncode: filed to convert to public key");
        return false;
    }

    size_t expected_length;
    if (!EVP_EncodedLength(&expected_length, sizeof(binary_key_data)))
    {
        LogFailed("EVP_EncodedLength: public key too large to base64 encode");
        return false;
    }

    out->resize(expected_length);
    size_t actual_length = EVP_EncodeBlock(reinterpret_cast<uint8_t *>(out->data()), binary_key_data,
                                           sizeof(binary_key_data));
    out->resize(actual_length);
    out->append(" ");
    out->append("Bzi-Han"); // Login user name
    out->append("@");
    out->append("GOOGLE-ADB"); // Network host name
    return true;
}

bssl::UniquePtr<EVP_PKEY> CreateRSA2048PrivateKey()
{
    bssl::UniquePtr<EVP_PKEY> pkey(EVP_PKEY_new());
    bssl::UniquePtr<BIGNUM> exponent(BN_new());
    bssl::UniquePtr<RSA> rsa(RSA_new());
    if (!pkey || !exponent || !rsa)
    {
        LogFailed("CreateRSA2048PrivateKey: failed to allocate key");
        return {};
    }

    BN_set_word(exponent.get(), RSA_F4);
    RSA_generate_key_ex(rsa.get(), 2048, exponent.get(), nullptr);
    EVP_PKEY_set1_RSA(pkey.get(), rsa.get());

    return pkey;
}

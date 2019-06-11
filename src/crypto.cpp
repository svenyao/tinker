//
// Created by sven on 6/6/17.
//

#include "crypto.h"

#include <string.h>
#include <sstream>
#include <openssl/bn.h>
#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/md5.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/ossl_typ.h>

// linux下编译错误，声明宏用于禁用mdc2
#define OPENSSL_NO_MDC2

namespace tinker{

static void BN2String(const BIGNUM* bn, std::string& n, BNStringType type)
{
  if (!bn) return;
  switch (type)
  {
  case kBin:
    n.resize(BN_num_bytes(bn));
    BN_bn2bin(bn, (unsigned char*)n.data());
    break;
  case kHex:
    char* str = BN_bn2hex(bn);
    if (!str) break;
    n.assign(str);
    OPENSSL_free(str);
    break;
  }
}

static void String2BN(const std::string& n, BIGNUM** bn, BNStringType type)
{
  if (!bn) return;
  BIGNUM* ret = NULL;
  switch (type)
  {
  case kBin:
    ret = BN_bin2bn((const unsigned char*)n.data(), (int)n.length(), *bn);
    if (*bn == NULL) *bn = ret;
    break;
  case kHex:
    BN_hex2bn(bn, n.c_str());
    break;
  }
}

// 
static const evp_md_st* /*Digest::*/get_evp_md(EvpMdType md_type) {
  //const EVP_MD* evp_md;
  switch (md_type) {
  case tinker::evp_md_null:
    return ::EVP_md_null();
#ifndef OPENSSL_NO_MD2
  case tinker::evp_md2:
    return ::EVP_md2();
#endif
#ifndef OPENSSL_NO_MD4
  case tinker::evp_md4:
    return ::EVP_md4();
#endif
#ifndef OPENSSL_NO_MD5
  case tinker::evp_md5:
    return ::EVP_md5();
  case tinker::evp_md5_sha1:
    return ::EVP_md5_sha1();
#endif
#ifndef OPENSSL_NO_BLAKE2
  case tinker::evp_blake2b512:
    return ::EVP_blake2b512();
  case tinker::evp_blake2s256:
    return ::EVP_blake2s256();
#endif
#ifndef OPENSSL_NO_SHA
  case tinker::evp_sha1:
    return ::EVP_sha1();
//  case tinker::evp_dss:
//    return ::EVP_dss();
//  case tinker::evp_dss1:
//    return ::EVP_dss1();
//  case tinker::evp_ecdsa:
//    return ::EVP_ecdsa();
#endif
#ifndef OPENSSL_NO_SHA256
  case tinker::evp_sha224:
    return ::EVP_sha224();
  case tinker::evp_sha256:
    return ::EVP_sha256();
#endif
#ifndef OPENSSL_NO_SHA512
  case tinker::evp_sha384:
    return ::EVP_sha384();
  case tinker::evp_sha512:
    return ::EVP_sha512();
#endif
#ifndef OPENSSL_NO_MDC2
  case tinker::evp_mdc2:
    return ::EVP_mdc2();
#endif
#ifndef OPENSSL_NO_RIPEMD
  case tinker::evp_ripemd160:
    return ::EVP_ripemd160();
#endif
#ifndef OPENSSL_NO_WHIRLPOOL
  case tinker::evp_whirlpool:
    return ::EVP_whirlpool();
#endif
  default:
    break;
  }
  return ::EVP_md_null();
};

//
static const EVP_CIPHER* get_evp_cipher(EvpCipherType cipher_type){
  switch (cipher_type){
    case tinker::evp_enc_null:  /* does nothing : -) */
      return EVP_enc_null();
# ifndef OPENSSL_NO_DES
    case tinker::evp_des_ecb:
      return EVP_des_ecb();
    case tinker::evp_des_ede:
      return EVP_des_ede();
    case tinker::evp_des_ede3:
      return EVP_des_ede3();
    case tinker::evp_des_ede_ecb:
      return EVP_des_ede_ecb();
    case tinker::evp_des_ede3_ecb:
      return EVP_des_ede3_ecb();
    case tinker::evp_des_cfb:
      return EVP_des_cfb();
    case tinker::evp_des_cfb1:
      return EVP_des_cfb1();
    case tinker::evp_des_cfb8:
      return EVP_des_cfb8();
    case tinker::evp_des_ede_cfb:
      return EVP_des_ede_cfb();
    case tinker::evp_des_ede3_cfb:
      return EVP_des_ede3_cfb();
    case tinker::evp_des_ede3_cfb1:
      return EVP_des_ede3_cfb1();
    case tinker::evp_des_ede3_cfb8:
      return EVP_des_ede3_cfb8();
    case tinker::evp_des_ofb:
      return EVP_des_ofb();
    case tinker::evp_des_ede_ofb:
      return EVP_des_ede_ofb();
    case tinker::evp_des_ede3_ofb:
      return EVP_des_ede3_ofb();
    case tinker::evp_des_cbc:
      return EVP_des_cbc();
    case tinker::evp_des_ede_cbc:
      return EVP_des_ede_cbc();
    case tinker::evp_des_ede3_cbc:
      return EVP_des_ede3_cbc();
    case tinker::evp_desx_cbc:
      return EVP_desx_cbc();
//    case tinker::evp_des_ede3_wrap:
//      return EVP_des_ede3_wrap();
# endif
# ifndef OPENSSL_NO_RC4
    case tinker::evp_rc4:
      return EVP_rc4();
    case tinker::evp_rc4_40:
      return EVP_rc4_40();
#  ifndef OPENSSL_NO_MD5
    case tinker::evp_rc4_hmac_md5:
      return EVP_rc4_hmac_md5();
#  endif
# endif
# ifndef OPENSSL_NO_IDEA
    case tinker::evp_idea_ecb:
      return EVP_idea_ecb();
    case tinker::evp_idea_cfb:
      return EVP_idea_cfb();
    case tinker::evp_idea_ofb:
      return EVP_idea_ofb();
    case tinker::evp_idea_cbc:
      return EVP_idea_cbc();
# endif
# ifndef OPENSSL_NO_RC2
    case tinker::evp_rc2_ecb:
      return EVP_rc2_ecb();
    case tinker::evp_rc2_cbc:
      return EVP_rc2_cbc();
    case tinker::evp_rc2_40_cbc:
      return EVP_rc2_40_cbc();
    case tinker::evp_rc2_64_cbc:
      return EVP_rc2_64_cbc();
    case tinker::evp_rc2_cfb:
      return EVP_rc2_cfb();
    case tinker::evp_rc2_ofb:
      return EVP_rc2_ofb();
# endif
# ifndef OPENSSL_NO_BF
    case tinker::evp_bf_ecb:
      return EVP_bf_ecb();
    case tinker::evp_bf_cbc:
      return EVP_bf_cbc();
    case tinker::evp_bf_cfb:
      return EVP_bf_cfb();
    case tinker::evp_bf_ofb:
      return EVP_bf_ofb();
# endif
# ifndef OPENSSL_NO_CAST
    case tinker::evp_cast5_ecb:
      return EVP_cast5_ecb();
    case tinker::evp_cast5_cbc:
      return EVP_cast5_cbc();
    case tinker::evp_cast5_cfb:
      return EVP_cast5_cfb();
    case tinker::evp_cast5_ofb:
      return EVP_cast5_ofb();
# endif
#ifndef OPENSSL_NO_RC5
    case tinker::evp_rc5_32_12_16_cbc:
      return EVP_rc5_32_12_16_cbc();
    case tinker::evp_rc5_32_12_16_ecb:
      return EVP_rc5_32_12_16_ecb();
    case tinker::evp_rc5_32_12_16_cfb:
      return EVP_rc5_32_12_16_cfb();
    case tinker::evp_rc5_32_12_16_ofb:
      return EVP_rc5_32_12_16_ofb();
# endif
# ifndef OPENSSL_NO_AES
    case tinker::evp_aes_128_ecb:
      return EVP_aes_128_ecb();
    case tinker::evp_aes_128_cbc:
      return EVP_aes_128_cbc();
    case tinker::evp_aes_128_cfb1:
      return EVP_aes_128_cfb1();
    case tinker::evp_aes_128_cfb8:
      return EVP_aes_128_cfb8();
    case tinker::evp_aes_128_cfb:
      return EVP_aes_128_cfb();
    case tinker::evp_aes_128_ofb:
      return EVP_aes_128_ofb();
    case tinker::evp_aes_128_ctr:
      return EVP_aes_128_ctr();
    case tinker::evp_aes_128_ccm:
      return EVP_aes_128_ccm();
    case tinker::evp_aes_128_gcm:
      return EVP_aes_128_gcm();
    case tinker::evp_aes_128_xts:
      return EVP_aes_128_xts();
//    case tinker::evp_aes_128_wrap:
//      return EVP_aes_128_wrap();
    case tinker::evp_aes_192_ecb:
      return EVP_aes_192_ecb();
    case tinker::evp_aes_192_cbc:
      return EVP_aes_192_cbc();
    case tinker::evp_aes_192_cfb1:
      return EVP_aes_192_cfb1();
    case tinker::evp_aes_192_cfb8:
      return EVP_aes_192_cfb8();
    case tinker::evp_aes_192_cfb:
      return EVP_aes_192_cfb();
    case tinker::evp_aes_192_ofb:
      return EVP_aes_192_ofb();
    case tinker::evp_aes_192_ctr:
      return EVP_aes_192_ctr();
    case tinker::evp_aes_192_ccm:
      return EVP_aes_192_ccm();
    case tinker::evp_aes_192_gcm:
      return EVP_aes_192_gcm();
//    case tinker::evp_aes_192_wrap:
//      return EVP_aes_192_wrap();
    case tinker::evp_aes_256_ecb:
      return EVP_aes_256_ecb();
    case tinker::evp_aes_256_cbc:
      return EVP_aes_256_cbc();
    case tinker::evp_aes_256_cfb1:
      return EVP_aes_256_cfb1();
    case tinker::evp_aes_256_cfb8:
      return EVP_aes_256_cfb8();
    case tinker::evp_aes_256_cfb:
      return EVP_aes_256_cfb();
    case tinker::evp_aes_256_ofb:
      return EVP_aes_256_ofb();
    case tinker::evp_aes_256_ctr:
      return EVP_aes_256_ctr();
    case tinker::evp_aes_256_ccm:
      return EVP_aes_256_ccm();
    case tinker::evp_aes_256_gcm:
      return EVP_aes_256_gcm();
    case tinker::evp_aes_256_xts:
      return EVP_aes_256_xts();
//    case tinker::evp_aes_256_wrap:
//      return EVP_aes_256_wrap();
#  if !defined(OPENSSL_NO_SHA) && !defined(OPENSSL_NO_SHA1)
    case tinker::evp_aes_128_cbc_hmac_sha1:
      return EVP_aes_128_cbc_hmac_sha1();
    case tinker::evp_aes_256_cbc_hmac_sha1:
      return EVP_aes_256_cbc_hmac_sha1();
#  endif
#  ifndef OPENSSL_NO_SHA256
//    case tinker::evp_aes_128_cbc_hmac_sha256:
//      return EVP_aes_128_cbc_hmac_sha256();
//    case tinker::evp_aes_256_cbc_hmac_sha256:
//      return EVP_aes_256_cbc_hmac_sha256();
#  endif
# endif
# ifndef OPENSSL_NO_CAMELLIA
    case tinker::evp_camellia_128_ecb:
      return EVP_camellia_128_ecb();
    case tinker::evp_camellia_128_cbc:
      return EVP_camellia_128_cbc();
    case tinker::evp_camellia_128_cfb1:
      return EVP_camellia_128_cfb1();
    case tinker::evp_camellia_128_cfb8:
      return EVP_camellia_128_cfb8();
    case tinker::evp_camellia_128_cfb:
      return EVP_camellia_128_cfb();
    case tinker::evp_camellia_128_ofb:
      return EVP_camellia_128_ofb();
    case tinker::evp_camellia_192_ecb:
      return EVP_camellia_192_ecb();
    case tinker::evp_camellia_192_cbc:
      return EVP_camellia_192_cbc();
    case tinker::evp_camellia_192_cfb1:
      return EVP_camellia_192_cfb1();
    case tinker::evp_camellia_192_cfb8:
      return EVP_camellia_192_cfb8();
    case tinker::evp_camellia_192_cfb:
      return EVP_camellia_192_cfb();
    case tinker::evp_camellia_192_ofb:
      return EVP_camellia_192_ofb();
    case tinker::evp_camellia_256_ecb:
      return EVP_camellia_256_ecb();
    case tinker::evp_camellia_256_cbc:
      return EVP_camellia_256_cbc();
    case tinker::evp_camellia_256_cfb1:
      return EVP_camellia_256_cfb1();
    case tinker::evp_camellia_256_cfb8:
      return EVP_camellia_256_cfb8();
    case tinker::evp_camellia_256_cfb:
      return EVP_camellia_256_cfb();
    case tinker::evp_camellia_256_ofb:
      return EVP_camellia_256_ofb();
# endif
# ifndef OPENSSL_NO_SEED
    case tinker::evp_seed_ecb:
      return EVP_seed_ecb();
    case tinker::evp_seed_cbc:
      return EVP_seed_cbc();
    case tinker::evp_seed_cfb:
      return EVP_seed_cfb();
    case tinker::evp_seed_ofb:
      return EVP_seed_ofb();
# endif
    default:
      break;
  }
  return EVP_enc_null();
}


Digest::Digest()
  :evp_md_(::EVP_sha1()),
   ctx_(EVP_MD_CTX_create())
{
}

Digest::Digest(EvpMdType evp_md_type)
  : evp_md_(get_evp_md(evp_md_type)),
    ctx_(EVP_MD_CTX_create())
{

}

Digest::~Digest()
{
  EVP_MD_CTX_destroy(ctx_);
}

int Digest::Init()
{
  //EVP_MD_CTX_cleanup(ctx_);
  EVP_MD_CTX_init(ctx_);
  return EVP_DigestInit_ex(ctx_, evp_md_, NULL) ? 0 : -1;
}

int Digest::Update(const std::string& message)
{
  return EVP_DigestUpdate(ctx_, message.data(), message.length()) ? 0 : -1;
}

int Digest::Final(std::string& digest, BNStringType type)
{
  digest.resize(EVP_MAX_MD_SIZE);
  unsigned int size = 0;
  if (!EVP_DigestFinal_ex(ctx_, (unsigned char*)digest.data(), &size))
    return -1;
  digest.resize(size);

  if (type == kHex)
  {
    std::ostringstream oss;
    for (size_t idx = 0; idx < digest.size(); ++idx)
    {
      oss << std::hex << ((digest[idx] >> 4) & 0xf) << (digest[idx] & 0xf);
    }
    digest = oss.str();
  }
  return 0;
}

int Digest::MessageDigest(const std::string& message, std::string& digest, BNStringType type) const
{
  digest.resize(EVP_MAX_MD_SIZE);
  unsigned int size = 0;
  if (!EVP_Digest(message.data(), message.length(), (unsigned char*)digest.data(), &size, evp_md_, NULL))
    return -1;
  digest.resize(size);

  if (type == kHex)
  {
    std::ostringstream oss;
    for (size_t idx = 0; idx < digest.size(); ++idx)
    {
      oss << std::hex << ((digest[idx] >> 4) & 0xf) << (digest[idx] & 0xf);
    }
    digest = oss.str();
  }
  return 0;
}

int Digest::Type() const
{
  return EVP_MD_type(evp_md_);
}

int Digest::Size() const
{
  return EVP_MD_size(evp_md_);
}

int Digest::BlockSize() const
{
  return EVP_MD_block_size(evp_md_);
}

//
Crypto::Crypto():cipher_(EVP_bf_cbc()){
}
Crypto::Crypto(EvpCipherType cipher_type){
  cipher_ = get_evp_cipher(cipher_type);
}
Crypto::~Crypto(){
}

int Crypto::Encrypt(const std::string& instr, const std::string& key, std::string& outstr) const
{
  return DoCrypt(instr, key, outstr, 1, cipher_);
}

int Crypto::Decrypt(const std::string& instr, const std::string& key, std::string& outstr) const
{
  return DoCrypt(instr, key, outstr, 0, cipher_);
}

int Crypto::DoCrypt(const std::string& instr, const std::string& key, std::string& outstr, int enc, const EVP_CIPHER* cipher) const
{
  int ret = -1;
  unsigned char* buf = NULL;
  EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
  EVP_CIPHER_CTX_reset(ctx);
  //EVP_CIPHER_CTX_init(&ctx);
  EVP_CipherInit_ex(ctx, cipher, NULL, NULL, NULL, enc);
  EVP_CIPHER_CTX_set_key_length(ctx, (int)key.length());
  EVP_CipherInit_ex(ctx, NULL, NULL, (unsigned char*)key.c_str(), NULL, enc);
  buf = new unsigned char[instr.length() + EVP_MAX_BLOCK_LENGTH];
  int len = 0;
  size_t total = 0;
  if (!EVP_CipherUpdate(ctx, buf, &len, (unsigned char*)instr.c_str(), (int)instr.length()))
    goto out;
  total += len;
  if (!EVP_CipherFinal_ex(ctx, buf + total, &len))
    goto out;
  total += len;
  outstr.assign((char*)buf, total);
  ret = 0;
out:
  //EVP_CIPHER_CTX_cleanup(ctx);
  EVP_CIPHER_CTX_free(ctx);
  if (buf) delete[] buf;
  return ret;
}


RSACrypto::RSACrypto()
  : rsa_(NULL)
{
  rsa_ = RSA_new();
}

RSACrypto::~RSACrypto()
{
  RSA_free(rsa_);
}

int RSACrypto::GenRSA(int bits)
{
  bignum_st* bn_e = BN_new();
  BN_set_word(bn_e, RSA_F4);
  int ret = RSA_generate_key_ex(rsa_, bits, bn_e, NULL);
  BN_free(bn_e);
  return ret;
}

int RSACrypto::RSASize() const
{
  return RSA_size(rsa_);
}

void RSACrypto::Reset()
{
  RSA_free(rsa_);
  rsa_ = RSA_new();
}
bool RSACrypto::IsPublicKey() const
{
  bignum_st* bn_n;
  bignum_st* bn_e;
  RSA_get0_key(rsa_, (const BIGNUM**)&bn_n, (const BIGNUM**)&bn_e, NULL);
  return (bn_n && bn_e);
}

bool RSACrypto::IsPrivateKey() const
{
  bignum_st* bn_n;
  bignum_st* bn_e;
  bignum_st* bn_d;
  RSA_get0_key(rsa_, (const BIGNUM**)&bn_n, (const BIGNUM**)&bn_e, (const BIGNUM**)&bn_d);

  return (bn_n && bn_e && bn_d);
}

void RSACrypto::GetPublicKey(std::string& n, std::string& e, BNStringType type) const
{
  bignum_st* bn_n;
  bignum_st* bn_e;
  RSA_get0_key(rsa_, (const BIGNUM**)&bn_n, (const BIGNUM**)&bn_e, NULL);
  BN2String(bn_n, n, type);
  BN2String(bn_e, e, type);
}

void RSACrypto::GetPrivateKey(std::string& n, std::string& e, std::string& d, BNStringType type) const
{
  bignum_st* bn_n;
  bignum_st* bn_e;
  bignum_st* bn_d;
  RSA_get0_key(rsa_, (const BIGNUM**)&bn_n, (const BIGNUM**)&bn_e, (const BIGNUM**)&bn_d);
  BN2String(bn_n, n, type);
  BN2String(bn_e, e, type);
  BN2String(bn_d, d, type);
}

void RSACrypto::SetPublicKey(const std::string& n, const std::string& e, BNStringType type)
{
  bignum_st* bn_n;
  bignum_st* bn_e;
  String2BN(n, &bn_n, type);
  String2BN(e, &bn_e, type);

  RSA_set0_key(rsa_, bn_n, bn_e, NULL);
}

void RSACrypto::SetPrivateKey(const std::string& n, const std::string& e, const std::string& d, BNStringType type)
{
  bignum_st* bn_n;
  bignum_st* bn_e;
  bignum_st* bn_d;
  String2BN(n, &bn_n, type);
  String2BN(e, &bn_e, type);
  String2BN(d, &bn_d, type);

  RSA_set0_key(rsa_, bn_n, bn_e, bn_d);
}

int RSACrypto::PublicEncrypt(const std::string& instr, std::string& outstr) const
{
  if (!IsPublicKey()) return -1;
  int flen = RSASize();
  outstr.resize(flen);
  if (!RSA_public_encrypt(flen, (const unsigned char*)instr.data(), (unsigned char*)outstr.data(), rsa_, RSA_NO_PADDING))
    return -1;
  return 0;
}

int RSACrypto::PrivateDecrypt(const std::string& instr, std::string& outstr) const
{
  if (!IsPrivateKey()) return -1;
  int flen = RSASize();
  outstr.resize(flen);
  if (!RSA_private_decrypt(flen, (const unsigned char*)instr.data(), (unsigned char*)outstr.data(), rsa_, RSA_NO_PADDING))
    return -1;
  return 0;
}

int RSACrypto::PrivateEncrypt(const std::string& instr, std::string& outstr) const
{
  if (!IsPrivateKey()) return -1;
  int flen = RSASize();
  outstr.resize(flen);
  if (!RSA_private_encrypt(flen, (const unsigned char*)instr.data(), (unsigned char*)outstr.data(), rsa_, RSA_NO_PADDING))
    return -1;
  return 0;
}

int RSACrypto::PublicDecrypt(const std::string& instr, std::string& outstr) const
{
  if (!IsPublicKey()) return -1;
  int flen = RSASize();
  outstr.resize(flen);
  if (!RSA_public_decrypt(flen, (const unsigned char*)instr.data(), (unsigned char*)outstr.data(), rsa_, RSA_NO_PADDING))
    return -1;
  return 0;
}

int RSACrypto::Sign(const std::string& digest, std::string& sign, int type) const
{
  if (!IsPrivateKey()) return -1;
  int flen = RSASize();
  sign.resize(flen);
  unsigned int signlen = 0;
  if (!RSA_sign(type, (const unsigned char*)digest.data(), (unsigned int)digest.length(), (unsigned char*)sign.data(), &signlen, rsa_))
  {
    // test code.
    unsigned long flags;
    flags = ERR_peek_last_error();
    ERR_load_crypto_strings();
    char buf[1024] = { 0 };
    ERR_error_string(flags, buf);
    //trace_print(std::string(buf).append("\r\n"));
    return -1;
  }
  sign.resize(signlen);
  return 0;
}

int RSACrypto::Verify(const std::string& digest, const std::string& sign, int type) const
{
  if (!IsPublicKey()) return 0;
  int vret =  RSA_verify(type, (const unsigned char*)digest.data(), (unsigned int)digest.length(),
               (const unsigned char*)sign.data(), (unsigned int)sign.length(), rsa_) == 1;
  //
  if (vret != 1)
  {
    // test code.
    unsigned long flags;
    flags = ERR_peek_last_error();
    ERR_load_crypto_strings();
    char buf[1024] = { 0 };
    ERR_error_string(flags, buf);
    //trace_print(std::string(buf).append("\r\n"));
    return -1;
  }
  return 0;
}

int RSACrypto::get_evp_md_type(EvpMdType md_type)
{
  return EVP_MD_type(get_evp_md(md_type));
}

int DigestSign::Sign(const RSACrypto& crypto, EvpMdType md_type/*const Digest& digest*/, const std::string& data, std::string& sign)
{
  if (!crypto.IsPrivateKey()) return -1;
  std::string md;
  if (md_type != evp_md5_sha1)
  {
    Digest digest(md_type);
    if (digest.MessageDigest(data, md) < 0)
      return false;

    return crypto.Sign(md, sign, digest.Type());
  }
  else
  {
    std::string md5_md;
    Digest digest_md5(evp_md5);
    if (digest_md5.MessageDigest(data, md5_md) < 0)
      return false;
    std::string sha_md;
    Digest digest_sha1(evp_sha1);
    if (digest_sha1.MessageDigest(data, sha_md) < 0)
      return false;
    md = md5_md.append(sha_md);

    return crypto.Sign(md, sign, NID_md5_sha1);
  }
}

int DigestSign::Verify(const RSACrypto& crypto, EvpMdType md_type/*const Digest& digest*/, const std::string& data, const std::string& sign)
{
  if (!crypto.IsPublicKey()) return false;
  std::string md;
  if (md_type != evp_md5_sha1)
  {
    Digest digest(md_type);
    if (digest.MessageDigest(data, md) < 0)
      return false;

    return crypto.Verify(md, sign, digest.Type());
  }
  else
  {
    std::string md5_md;
    Digest digest_md5(evp_md5);
    if (digest_md5.MessageDigest(data, md5_md) < 0)
      return false;
    std::string sha_md;
    Digest digest_sha1(evp_sha1);
    if (digest_sha1.MessageDigest(data, sha_md) < 0)
      return false;
    md = md5_md.append(sha_md);

    return crypto.Verify(md, sign, NID_md5_sha1);
  }
}

int Base64::Encode(const std::string& input, std::string& output, bool with_new_line /*= false*/)
{
  BIO * bmem = NULL;
  BIO * b64 = NULL;
  BUF_MEM * bptr = NULL;

  b64 = BIO_new(BIO_f_base64());
  if (!with_new_line)
  {
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
  }
  bmem = BIO_new(BIO_s_mem());
  b64 = BIO_push(b64, bmem);
  BIO_write(b64, input.data(), input.length());
  BIO_flush(b64);
  BIO_get_mem_ptr(b64, &bptr);

  char * buff = (char *)malloc(bptr->length + 1);
  memcpy(buff, bptr->data, bptr->length);
  buff[bptr->length] = '\0';

  BIO_free_all(b64);
  output = buff;
  free(buff);
  return 0;
}

//
//  create by sven 2015-11-19
//
static const int base64DecodeChars[] =
{
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
  -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
  52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
  -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
  15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
  -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
  41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1
};
// 重写base64解码算法，不能使用openssl的base64解码。
static std::string base64decode(const std::string& str)
{
  int c1, c2, c3, c4;
  unsigned int i, len;
  std::string out;

  len = str.length();
  i = 0;
  out = "";
  while (i < len)
  {
    /* c1 */
    do
    {
      c1 = base64DecodeChars[str[(i++)] & 0xff];
    }
    while (i < len && c1 == -1);
    if (c1 == -1)
      break;

    /* c2 */
    do
    {
      c2 = base64DecodeChars[str[(i++)] & 0xff];
    }
    while (i < len && c2 == -1);
    if (c2 == -1)
      break;

    out += (char)((c1 << 2) | ((c2 & 0x30) >> 4));

    /* c3 */
    do
    {
      c3 = str[(i++)] & 0xff;
      if (c3 == 61)
        return out;
      c3 = base64DecodeChars[c3];
    }
    while (i < len && c3 == -1);
    if (c3 == -1)
      break;

    out += (char)(((c2 & 0xF) << 4) | ((c3 & 0x3C) >> 2));

    /* c4 */
    do
    {
      c4 = str[(i++)] & 0xff;
      if (c4 == 61)
        return out;
      c4 = base64DecodeChars[c4];
    }
    while (i < len && c4 == -1);
    if (c4 == -1)
      break;
    out += (char)(((c3 & 0x03) << 6) | c4);
  }
  return std::move(out);
}
int Base64::Decode(const std::string& input, std::string& output, bool with_new_line /*= false*/)
{
  if (with_new_line)
  {
    int length = input.length();
    BIO * b64 = NULL;
    BIO * bmem = NULL;
    char * buffer = (char *)malloc(length);
    memset(buffer, 0, length);

    b64 = BIO_new(BIO_f_base64());
    if (!with_new_line)
    {
      BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    }
    bmem = BIO_new_mem_buf((void *)input.data(), length);
    bmem = BIO_push(b64, bmem);
    BIO_read(bmem, buffer, length);

    BIO_free_all(bmem);
    output = buffer;
    free(buffer);
  }
  else
  {
    output = base64decode(input);
  }
  return 0;
}

}//!namespace tinker
//
// Created by sven on 6/6/17.
//
#ifndef FGS_CRYPTO_H__
#define FGS_CRYPTO_H__

#include <string>

struct evp_cipher_st;
struct evp_md_st;
struct evp_md_ctx_st;
struct rsa_st;
struct bignum_st;

namespace tinker {

// 摘要算法类型
enum EvpMdType{
  evp_md_null = 0, evp_md2, evp_md4, evp_md5, evp_md5_sha1, evp_blake2b512,evp_blake2s256, evp_sha1,/* evp_dss, evp_dss1, evp_ecdsa,*/
  evp_sha224, evp_sha256, evp_sha384, evp_sha512, evp_mdc2, evp_ripemd160, evp_whirlpool
};
// 对称加密算法类型
enum EvpCipherType{
  evp_enc_null = 0,
  // des
  evp_des_ecb, evp_des_ede, evp_des_ede3, evp_des_ede_ecb, evp_des_ede3_ecb, evp_des_cfb,
  evp_des_cfb1, evp_des_cfb8, evp_des_ede_cfb, evp_des_ede3_cfb, evp_des_ede3_cfb1, evp_des_ede3_cfb8,
  evp_des_ofb, evp_des_ede_ofb, evp_des_ede3_ofb, evp_des_cbc, evp_des_ede_cbc, evp_des_ede3_cbc,
  evp_desx_cbc, evp_des_ede3_wrap,
  // rc
  evp_rc4, evp_rc4_40, evp_rc4_hmac_md5,
  evp_idea_ecb, evp_idea_cfb, evp_idea_ofb, evp_idea_cbc,
  evp_rc2_ecb, evp_rc2_cbc, evp_rc2_40_cbc, evp_rc2_64_cbc, evp_rc2_cfb, evp_rc2_ofb,
  evp_bf_ecb, evp_bf_cbc, evp_bf_cfb, evp_bf_ofb,
  evp_cast5_ecb, evp_cast5_cbc, evp_cast5_cfb, evp_cast5_ofb,
  evp_rc5_32_12_16_cbc, evp_rc5_32_12_16_ecb, evp_rc5_32_12_16_cfb, evp_rc5_32_12_16_ofb,
  // aes
  evp_aes_128_ecb, evp_aes_128_cbc, evp_aes_128_cfb1, evp_aes_128_cfb8, evp_aes_128_cfb, evp_aes_128_ofb,
  evp_aes_128_ctr, evp_aes_128_ccm, evp_aes_128_gcm, evp_aes_128_xts, evp_aes_128_wrap, evp_aes_192_ecb,
  evp_aes_192_cbc, evp_aes_192_cfb1, evp_aes_192_cfb8, evp_aes_192_cfb, evp_aes_192_ofb, evp_aes_192_ctr,
  evp_aes_192_ccm, evp_aes_192_gcm, evp_aes_192_wrap, evp_aes_256_ecb, evp_aes_256_cbc, evp_aes_256_cfb1,
  evp_aes_256_cfb8, evp_aes_256_cfb, evp_aes_256_ofb, evp_aes_256_ctr, evp_aes_256_ccm, evp_aes_256_gcm,
  evp_aes_256_xts, evp_aes_256_wrap, evp_aes_128_cbc_hmac_sha1, evp_aes_256_cbc_hmac_sha1,
  evp_aes_128_cbc_hmac_sha256, evp_aes_256_cbc_hmac_sha256,
  // camellia
  evp_camellia_128_ecb, evp_camellia_128_cbc, evp_camellia_128_cfb1, evp_camellia_128_cfb8,
  evp_camellia_128_cfb, evp_camellia_128_ofb, evp_camellia_192_ecb, evp_camellia_192_cbc,
  evp_camellia_192_cfb1, evp_camellia_192_cfb8, evp_camellia_192_cfb, evp_camellia_192_ofb,
  evp_camellia_256_ecb, evp_camellia_256_cbc, evp_camellia_256_cfb1, evp_camellia_256_cfb8,
  evp_camellia_256_cfb, evp_camellia_256_ofb,
  // seed
  evp_seed_ecb, evp_seed_cbc, evp_seed_cfb, evp_seed_ofb,
};
enum BNStringType{
  kBin = 0,
  kHex,
};
//摘要
class Digest{
public:
  Digest();//默认sha1
  explicit Digest(EvpMdType evp_md_type);
  ~Digest();
  int Init();
  int Update(const std::string& message);
  int Final(std::string& digest, BNStringType type = kBin);
  int MessageDigest(const std::string& message, std::string& digest, BNStringType type = kBin) const;
  int Type() const;
  int Size() const;
  int BlockSize() const;

private:
  Digest(const Digest&);
  void operator=(const Digest&);

  const evp_md_st* evp_md_;
  evp_md_ctx_st* ctx_;
};


//对称密钥加密，解密
class Crypto{
 public:
  Crypto(); // 默认采用blowfish加密算法(evp_bf_cbc)
  explicit Crypto(EvpCipherType cipher_type);
  ~Crypto();

  int Encrypt(const std::string& instr, const std::string& key, std::string& outstr) const;
  int Decrypt(const std::string& instr, const std::string& key, std::string& outstr) const;
 private:
  //enc = 1:加密  0:解密;  cipher: 参见openssl文档, 如EVP_bf_cbc()
  int DoCrypt(const std::string& instr, const std::string& key, std::string& outstr, int enc, const evp_cipher_st* cipher) const;
 private:
  Crypto(const Crypto&);
  void operator=(const Crypto&);
  const evp_cipher_st* cipher_;
};


//RSA非对称加密
class RSACrypto{
public:
  RSACrypto();
  ~RSACrypto();
  //生成一对公钥和私钥
  int GenRSA(int bits);
  //密钥长度
  int RSASize() const;
  void Reset();

  bool IsPublicKey() const;
  bool IsPrivateKey() const;

  void GetPublicKey(std::string& n, std::string& e, BNStringType type = kBin) const;
  void GetPrivateKey(std::string& n, std::string& e, std::string& d, BNStringType type = kBin) const;
  void SetPublicKey(const std::string& n, const std::string& e, BNStringType type = kBin);
  void SetPrivateKey(const std::string& n, const std::string& e, const std::string& d, BNStringType type = kBin);

  int PublicEncrypt(const std::string& instr, std::string& outstr) const;
  int PrivateDecrypt(const std::string& instr, std::string& outstr) const;
  int PrivateEncrypt(const std::string& instr, std::string& outstr) const;
  int PublicDecrypt(const std::string& instr, std::string& outstr) const;

  //type: 参见openssl文档, NID_md5, NID_sha1等
  int Sign(const std::string& digest, std::string& sign, int type) const;
  int Verify(const std::string& digest, const std::string& sign, int type) const;

  //
  int get_evp_md_type(EvpMdType md_type);

private:
  RSACrypto(const RSACrypto&);
  void operator=(const RSACrypto&);

  rsa_st* rsa_;
};

class DigestSign{
public:
  int Sign(const RSACrypto& crypto, EvpMdType md_type/*const Digest& digest*/, const std::string& data, std::string& sign);
  int Verify(const RSACrypto& crypto, EvpMdType md_type/*const Digest& digest*/, const std::string& data, const std::string& sign);
};

class Base64{
public:
  static int Encode(const std::string& input, std::string& output, bool with_new_line = false);
  static int Decode(const std::string& input, std::string& output, bool with_new_line = false);
};

}//!namespace fgs

#endif // FGS_CRYPTO_H__

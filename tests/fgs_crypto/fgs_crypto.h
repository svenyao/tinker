//
// Created by sven on 2/19/18.
//
#ifndef FGS_TGW_CRYPTO_H
#define FGS_TGW_CRYPTO_H
#include "crypto.h"
#include <string>

namespace tinker {

int tgw_crypto(const std::string& plaintext, std::string& ciphertext);

int tgw_getesn(const std::string& dsn, const std::string& mac, const std::string& cpuid, std::string& esn);

int get_md5(const std::string& plaintext, std::string& ciphertext);

int get_cpuid(std::string& cpu_id);
int get_dsn(std::string& serial_no);
int get_mac(std::string& mac_address);
int get_ip(std::string& ip);
int get_net_device(std::string& mac, std::string& ip);

} //!namespace fgs

#endif //FGS_TGW_CRYPTO_H

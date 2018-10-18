//
// Created by sven on 2/19/18.
//
#ifndef FGS_TGW_CRYPTO_H
#define FGS_TGW_CRYPTO_H
#include <string>

#ifdef _WIN32
#ifdef TGW_CRYPTO_EXPORTS
#	ifndef TGW_CRYPTO_API_STATIC
#	define	TGW_CRYPTO_API	__declspec(dllexport)
#	else
#	define TGW_CRYPTO_API
#	endif
#else
#	ifndef TGW_CRYPTO_API_STATIC
#	define	TGW_CRYPTO_API	__declspec(dllimport)
#	else
#	define TGW_CRYPTO_API
#	endif
#endif	// end TGW_CRYPTO_EXPORTS
#else
#	define	TGW_CRYPTO_API	 
#endif	// end _win32

namespace tinker {

int TGW_CRYPTO_API tgw_crypto(const std::string& plaintext, std::string& ciphertext);

int TGW_CRYPTO_API tgw_getesn(const std::string& dsn, const std::string& mac, const std::string& cpuid, std::string& esn);

int TGW_CRYPTO_API get_md5(const std::string& plaintext, std::string& ciphertext);

int TGW_CRYPTO_API get_cpuid(std::string& cpu_id);
int TGW_CRYPTO_API get_dsn(std::string& serial_no);
int TGW_CRYPTO_API get_mac(std::string& mac_address);
int TGW_CRYPTO_API get_ip(std::string& ip);
int TGW_CRYPTO_API get_net_device(std::string& mac, std::string& ip);

} //!namespace fgs

#endif //FGS_TGW_CRYPTO_H

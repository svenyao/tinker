/*
 * Copyright (C) 2018 LeHigh Hongking - All Rights Reserved.
 *
 * You may not use, distribute and modify this code for any
 * purpose unless you receive an official authorization from
 * Shenzhen LeHigh Hongking Technologies Co., Ltd.
 *
 * You should have received a copy of the license with this
 * file. If not, please write to: admin@hongkingsystem.cn,
 * or visit: http://hongkingsystem.cn
 */
#include "logging.h"
#include "tgw_crypto.h"
//
//#include <gtest/gtest.h>
//
//TEST(TgwGetEsn, get_esn) {
//  {
//    std::string dsn = "140129TF0501WH1B1R5R";
//    std::string mac = "bc968019b9c0";
//    std::string cpuid = "BFEBFBFF000306A9";
//    std::string esn;
//    tinker::tgw_getesn(dsn, mac, cpuid, esn);
//
////    LOG(info, "dsn: {}, mac: {}, cpuid: {}", dsn, mac, cpuid);
////    LOG(warn, "esn: {}", esn);
//    EXPECT_EQ("db624df2c45232a805582fb6c355432f65afb6045a875df24ce642ef13ceb8a8430b25"
//                  "c1ea65cbced7edfe9a49eb86a2b5f9fb10c8b27bcb5c6b4a483a906c12", esn);
//  }
////  LOG(trace, "---------------------------------");
//  {
//    std::string dsn = "";
//    std::string mac = "bc968019b9c0";
//    std::string cpuid = "BFEBFBFF000306A9";
//    std::string esn;
//    tinker::tgw_getesn(dsn, mac, cpuid, esn);
////    LOG(info, "dsn: {}, mac: {}, cpuid: {}", dsn, mac, cpuid);
////    LOG(warn, "esn: {}", esn);
//    EXPECT_EQ("58b5005fe4ca6f0cdc8f77102ab240cb9f55aabe7d05ce3551c85b9c21a6cce8b67e"
//                  "88850a53670b4e3f615ecf4e45228c5297cbd82e00eb5a3f6083fd402fb3", esn);
//  }
////  LOG(trace, "---------------------------------");
//  {
//    std::string dsn = "";
//    std::string mac = "201a062237bc";
//    std::string cpuid = "BFEBFBFF000306A9";
//    std::string esn;
//    tinker::tgw_getesn(dsn, mac, cpuid, esn);
////    LOG(info, "dsn: {}, mac: {}, cpuid: {}", dsn, mac, cpuid);
////    LOG(warn, "esn: {}", esn);
//    EXPECT_EQ("a803728981a1b7f979dc0b9f317fb47acfdacd7953452595f7852ec503"
//                  "ce0af9d4819cb8985b66b801cabb485d307ea86f2bcfd6eaa840aee482959c02ee318b", esn);
//  }
//}

int main(int argc, char** argv){
  scom::logging::instance().set_level(0);

  if (argc > 1) {
    std::string cl = argv[1];
    std::string md5;
    tinker::tgw_crypto(cl, md5);
    std::cout << "md5:" << md5 << std::endl;
    return 0;
  }
  std::string md5;
  tinker::tgw_crypto("mn8888", md5);
  std::cout << "crypto:" << md5 << std::endl;
  tinker::get_cpuid(md5);
  std::cout << "cpuid:" << md5 << std::endl;

  return 0;
//  testing::InitGoogleTest(&argc, argv);
//
//  return RUN_ALL_TESTS();
}

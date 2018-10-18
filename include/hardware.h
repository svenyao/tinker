//
// Created by sven on 4/5/17.
//

#ifndef TINKER_HARDWARE_H
#define TINKER_HARDWARE_H
#include "tinker_config.h"
#include <string>

namespace tinker {

class TINKER_API Hardware {
 public:
  static int GetCpuID(std::string& cpu_id);
  static int GetDiskSN(std::string& dsn);
  static int GetMac(std::string& mac);
  static int GetLocalIp(std::string& ip);

  // if ip not empty, then get mac for assign ip.
  static int GetNetDevice(std::string& mac, std::string& ip);
};

}//!namespace tinker


#endif //TINKER_HARDWARE_H

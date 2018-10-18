//
// Created by sven on 9/2/18.
//

#ifndef LIBSCOM_UNIQUE_ID_H
#define LIBSCOM_UNIQUE_ID_H
#include <stdint.h>
#include <atomic>

#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <time.h>
#define EPOCHFILETIME 11644473600000000Ui64
#else
#include <sys/time.h>
#include <stdio.h>
#define EPOCHFILETIME 11644473600000000ULL
#endif

//#define UUID_WORKER_THREAD_SAFE

namespace scom {

//twitter snowflake 算法
//64     63--------------22-----------12-----------0
//符号位 |    41位时间   | 10位机器吗 | 12位自增码 |
class unique_id {
 public:
  void set_epoch(uint64_t epoch) {
    epoch_ = epoch;
  }

  void set_machine(uint32_t machine) {
    machine_ = machine;
  }

  int64_t generate() {
    int64_t value = 0;
    uint64_t time = get_time() - epoch_;
    value = (time & 0x1FFFFFFFFFF) << 22;
    value |= (machine_ & 0x3FF) << 12;
    value |= ++sequence_ & 0xFFF;
    return value;
  }
 private:
  uint64_t epoch_{0};
  uint32_t machine_{0};
#ifdef UUID_WORKER_THREAD_SAFE
  std::atomic<uint64_t> sequence_{0};
#else
  uint64_t sequence_{0};
#endif

  uint64_t get_time() {
#ifdef _WIN32
    FILETIME filetime;
    uint64_t time = 0;
    GetSystemTimeAsFileTime(&filetime);
    time |= filetime.dwHighDateTime;
    time <<= 32;
    time |= filetime.dwLowDateTime;
    time /= 10000;
    time -= EPOCHFILETIME/10000;
    return time;
#else
    struct timeval tv;
    gettimeofday(&tv, NULL);
    uint64_t time = tv.tv_usec;
    time /= 1000;
    time += (tv.tv_sec * 1000);
    time -= EPOCHFILETIME/10000;
    return time;
#endif
  }
};

} //!namespace scom

#endif //LIBSCOM_UNIQUE_ID_H

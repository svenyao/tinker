//
// Created by sven on 6/21/17.
//

#ifndef LIBSCOM_SPIN_LOCK_H
#define LIBSCOM_SPIN_LOCK_H

#include <atomic>

namespace scom {

class spin_lock {
 public:
  void lock() {
    while (flag_.test_and_set(std::memory_order_acquire));
  }
  void unlock() {
    flag_.clear(std::memory_order_release);
  }
private:
#ifndef _WIN32
  std::atomic_flag flag_ = ATOMIC_FLAG_INIT;
#else
  std::atomic_flag flag_;
#endif
};

}//!namespace scom

#endif //LIBSCOM_SPIN_LOCK_H

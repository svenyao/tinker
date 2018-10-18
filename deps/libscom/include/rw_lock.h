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
#ifndef LIBSCOM_RW_LOCK_H
#define LIBSCOM_RW_LOCK_H
#include <mutex>
#include <condition_variable>

namespace scom {

class rw_lock {
 public:
  rw_lock() = default;
  ~rw_lock() = default;

  void read_lock() {
    std::unique_lock<std::mutex> lock(mtx_);
    cond_read_.wait(lock, [=]()->bool { return write_cnt_ == 0; });
    ++read_cnt_;
  }

  void read_unlock() {
    std::unique_lock<std::mutex> lock(mtx_);
    if (--read_cnt_ == 0 && write_cnt_ > 0) {
      cond_write_.notify_one();
    }
  }

  void write_lock() {
    std::unique_lock<std::mutex> lock(mtx_);
    ++write_cnt_;
    cond_write_.wait(lock, [=]()->bool { return read_cnt_ == 0 && !writing_flag_; });
    writing_flag_ = true;
  }

  void write_unlock() {
    std::unique_lock<std::mutex> lock(mtx_);
    if (--write_cnt_ == 0) {
      cond_read_.notify_all();
    }
    else {
      cond_write_.notify_one();
    }
    writing_flag_ = false;
  }

 private:
  volatile size_t read_cnt_{0};
  volatile size_t write_cnt_{0};
  volatile bool writing_flag_{false};
  std::mutex mtx_;
  std::condition_variable cond_read_;
  std::condition_variable cond_write_;
};

template <class _RWLOCK>
class read_guard {
 public:
  explicit read_guard(_RWLOCK& rw_lock)
      : rw_lock_(&rw_lock) {
    rw_lock_->read_lock();
  }
  ~read_guard() {
    rw_lock_->read_unlock();
  }
 private:
  read_guard() = delete;
  read_guard(const read_guard&) = delete;
  read_guard& operator=(const read_guard&) = delete;
  _RWLOCK* rw_lock_;
};

template <class _RWLOCK>
class write_guard {
 public:
  explicit write_guard(_RWLOCK& rw_lock)
      : rw_lock_(&rw_lock) {
      rw_lock_->write_lock();
  }
  ~write_guard() {
    rw_lock_->write_unlock();
  }
 private:
  write_guard() = delete;
  write_guard(const write_guard&) = delete;
  write_guard& operator=(const write_guard&) = delete;
  _RWLOCK* rw_lock_;
};

}//!namespace scom

#endif //LIBSCOM_RW_LOCK_H

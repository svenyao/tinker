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
#include "rw_lock.h"
#include "spin_lock.h"
#include <thread>
#include <vector>
#include <iostream>
#include <chrono>
#include <unordered_map>

using namespace scom;

class Counts {
 public:
  virtual int64_t read() = 0;
  virtual void write() = 0;
 protected:
  std::unordered_map<int64_t, int64_t> content_m_;

  void push(int64_t count) {
    //s_sleep(1);
    auto iter = content_m_.find(count%10000);
    if (iter != content_m_.end()) {
      iter->second = count;
    }
    else {
      content_m_.insert(std::make_pair(count%10000, count));
    }
  }

  int64_t get(int64_t count) {
    //s_sleep(1);
    auto iter = content_m_.find(count%10000);
    if (iter != content_m_.end()) {
      return iter->second;
    }
    return 0;
  }

};

class Counts_t1 : public Counts {
 public:
  int64_t read() {
    std::lock_guard<spin_lock> lock(mtx_);
    return get(idx_);
  }
  void write() {
    std::lock_guard<spin_lock> lock(mtx_);
    ++idx_;
    push(idx_);
  }
 private:
  int64_t idx_{0};
  spin_lock mtx_;
};

class Counts_t2  : public Counts {
 public:
  int64_t read() {
    read_guard<rw_lock> lock(mtx_);
    return get(idx_);
  }
  void write() {
    write_guard<rw_lock> lock(mtx_);
    ++idx_;
    push(idx_);
  }
 private:
  int64_t idx_{0};
  mutable rw_lock mtx_;
};
class Counts_t3  : public Counts {
 public:
  int64_t read() {
    std::lock_guard<std::mutex> lock(mtx_);
    return get(idx_);
  }
  void write() {
    std::lock_guard<std::mutex> lock(mtx_);
    ++idx_;
    push(idx_);
  }
 private:
  int64_t idx_{0};
  std::mutex mtx_;
};

class Counts_t4  : public Counts {
 public:
  int64_t read() {
    //s_sleep(1);
    return get(idx_);
  }
  void write() {
    //s_sleep(1);
    ++idx_;
    push(idx_);
  }
 private:
  std::atomic<int64_t> idx_{0};
};

void read_thread(Counts* ct_pt, uint32_t counts) {
  for (size_t idx = 0; idx < counts; ++idx) {
    ct_pt->read();
    //if (idx % 11 == 0) s_sleep(1);
  }
//  while (ct_pt->read() != counts*2) {
//
//  }
}

void write_thread(Counts* ct_pt, uint32_t counts) {
  for (size_t idx = 0; idx < counts; ++idx) {
    ct_pt->write();
//    if (counts < 100) {
//      std::cout << "thread: " << std::this_thread::get_id() << ", read idx:" << ct_pt->read() << std::endl;
//    }
//    if (idx % 101 == 0) s_sleep(1);
  }
}

using namespace std::chrono;

int main(int argc, char** argv) {
  uint32_t count = 1000000;
  if (argc >= 2) {
    count = atol(argv[1]);
  }

//  steady_clock::time_point tt1 = steady_clock::now();
#if 0
  auto func = [&](Counts *ct_pt) {
    std::vector<std::thread*> thread_arr;

    steady_clock::time_point t1 = steady_clock::now();
    for (size_t idx = 0; idx < 2; ++idx) {
      std::thread *thd = new std::thread(std::bind(write_thread, ct_pt, count));
      thread_arr.emplace_back(thd);
      std::cout << "start write thread: " << thd->get_id() << std::endl;
    }
    for (size_t idx = 0; idx < 4; ++idx) {
      std::thread *thd = new std::thread(std::bind(read_thread, ct_pt, count));
      thread_arr.emplace_back(thd);
      std::cout << "start read thread: " << thd->get_id() << std::endl;
    }
    for (auto& iter : thread_arr) {
      iter->join();
    }
    steady_clock::time_point t2 = steady_clock::now();
    duration<double> time_span = duration_cast<duration<double>>(t2 - t1);
    std::cout << "count:" << ct_pt->read() << ", time_span:" << time_span.count() << std::endl;

    for (auto& iter : thread_arr) {
      delete iter;
      iter = nullptr;
    }
    thread_arr.clear();
  };

  //
  std::cout << "start test spin_lock --------------" << std::endl;
  {
    Counts_t1 ct_pt;
    func(&ct_pt);
  }
  std::cout << "end test spin_lock --------------" << std::endl;
  std::cout << "start test rw_lock --------------" << std::endl;
  {
    Counts_t2 ct_pt;
    func(&ct_pt);
  }
  std::cout << "end test rw_lock --------------" << std::endl;
  std::cout << "start test std::mutex --------------" << std::endl;
  {
    Counts_t3 ct_pt;
    func(&ct_pt);
  }
  std::cout << "end test std::mutex --------------" << std::endl;
  std::cout << "start test atomic --------------" << std::endl;
  {
    Counts_t4 ct_pt;
    func(&ct_pt);
  }
  std::cout << "end test atomic --------------" << std::endl;
#endif

  {
    auto func_w = [&](Counts *ct_pt) {
      std::vector<std::thread*> thread_arr;

      steady_clock::time_point t1 = steady_clock::now();
      for (size_t idx = 0; idx < 4; ++idx) {
        std::thread *thd = new std::thread(std::bind(write_thread, ct_pt, count));
        thread_arr.emplace_back(thd);
        std::cout << "start write thread: " << thd->get_id() << std::endl;
      }
      for (auto& iter : thread_arr) {
        iter->join();
      }
      steady_clock::time_point t2 = steady_clock::now();
      duration<double> time_span = duration_cast<duration<double>>(t2 - t1);
      std::cout << "count:" << ct_pt->read() << ", write time_span:" << time_span.count() << std::endl;

      for (auto& iter : thread_arr) {
        delete iter;
        iter = nullptr;
      }
      thread_arr.clear();
    };

    auto func_r = [&](Counts *ct_pt) {
      std::vector<std::thread*> thread_arr;

      steady_clock::time_point t1 = steady_clock::now();
      for (size_t idx = 0; idx < 4; ++idx) {
        std::thread *thd = new std::thread(std::bind(read_thread, ct_pt, count));
        thread_arr.emplace_back(thd);
        std::cout << "start read thread: " << thd->get_id() << std::endl;
      }
      for (auto& iter : thread_arr) {
        iter->join();
      }
      steady_clock::time_point t2 = steady_clock::now();
      duration<double> time_span = duration_cast<duration<double>>(t2 - t1);
      std::cout << "count:" << ct_pt->read() << ", read time_span:" << time_span.count() << std::endl;

      for (auto& iter : thread_arr) {
        delete iter;
        iter = nullptr;
      }
      thread_arr.clear();
    };

    auto func = [&](Counts *ct_pt) {
      func_w(ct_pt);
      func_r(ct_pt);
    };

    std::cout << "start test spin_lock --------------" << std::endl;
    {
      Counts_t1 ct_pt;
      func(&ct_pt);
    }
    std::cout << "end test spin_lock --------------" << std::endl;
    std::cout << "start test rw_lock --------------" << std::endl;
    {
      Counts_t2 ct_pt;
      func(&ct_pt);
    }
    std::cout << "end test rw_lock --------------" << std::endl;
    std::cout << "start test std::mutex --------------" << std::endl;
    {
      Counts_t3 ct_pt;
      func(&ct_pt);
    }
    std::cout << "end test std::mutex --------------" << std::endl;
    std::cout << "start test std::atomic --------------" << std::endl;
    {
      Counts_t4 ct_pt;
      func(&ct_pt);
    }
    std::cout << "end test std::atomic --------------" << std::endl;
  }

//  steady_clock::time_point tt2 = steady_clock::now();
//  duration<double> time_span = duration_cast<duration<double>>(tt2 - tt1);
//  std::cout << "total time_span:" << time_span.count() << std::endl;
  return 0;
}

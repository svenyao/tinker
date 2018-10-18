//
// Created by sven on 7/22/18.
//

#ifndef LIBSCOM_LOCK_QUEUE_H
#define LIBSCOM_LOCK_QUEUE_H

#include "noncopyable.h"
#include <queue>
#include <mutex>
#include <condition_variable>

namespace scom {

template<typename T>
class lock_queue : public noncopyable {
 private:
  mutable std::mutex mtx;
  std::queue<T> data_queue;
  std::condition_variable data_cond;
 public:
  lock_queue() = default;

  void push(const T& new_value) {
    std::lock_guard<std::mutex> lk(mtx);
    data_queue.push(new_value);
    data_cond.notify_one();
  }

  T wait_and_pop() {
    std::unique_lock<std::mutex> lk(mtx);
    data_cond.wait(lk, [this]{ return !data_queue.empty(); });
    T res = std::move(data_queue.front());
    data_queue.pop();
    return std::move(res);
  }

  bool try_pop(T& value) {
    std::lock_guard<std::mutex> lk(mtx);
    if (data_queue.empty())
      return false;
    value = std::move(data_queue.front());
    data_queue.pop();
    return true;
  }

  bool empty() const {
    std::lock_guard<std::mutex> lk(mtx);
    return data_queue.empty();
  }

  size_t size() const {
    std::lock_guard<std::mutex> lk(mtx);
    return data_queue.size();
  }

  void clear() {
    std::lock_guard<std::mutex> lk(mtx);
    std::queue<T> queue_t;
    data_queue.swap(queue_t);
  }
};

}//!namespace scom

#endif //LIBSCOM_LOCK_QUEUE_H

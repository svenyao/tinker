//
// Created by sven on 7/22/18.
//

#ifndef LIBSCOM_UNLOCK_QUEUE_H
#define LIBSCOM_UNLOCK_QUEUE_H

#include "noncopyable.h"
#include <queue>
#include <thread>

namespace scom {

template<typename T>
class unlock_queue : public noncopyable {
 private:
  std::queue<T> data_queue;
 public:
  unlock_queue() = default;

  void push(const T& new_value) {
    data_queue.push(new_value);
  }

  T wait_and_pop() {
    while (true) {
      if (!data_queue.empty()) {
        T res = std::move(data_queue.front());
        data_queue.pop();
        return std::move(res);
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }
  }

  bool try_pop(T& value) {
    if (data_queue.empty())
      return false;
    value = std::move(data_queue.front());
    data_queue.pop();
    return true;
  }

  bool empty() const {
    return data_queue.empty();
  }

  size_t size() const {
    return data_queue.size();
  }

  void clear() {
    std::queue<T> queue_t;
    data_queue.swap(queue_t);
  }
};

}//!namespace scom

#endif //LIBSCOM_UNLOCK_QUEUE_H

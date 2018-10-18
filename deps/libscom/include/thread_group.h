//
// Created by sven on 7/16/18.
//

#ifndef thread_group_h__
#define thread_group_h__

#include <thread>
#include <mutex>
#include <list>
#include <memory>

namespace scom {

class thread_group {
 public:
  thread_group() {}
  ~thread_group() {
    for (auto it = threads_.begin(), end = threads_.end(); it != end; ++it) {
      delete *it;
    }
  }

  template<typename F>
  std::thread* create_thread(F thread_func) {
    std::lock_guard<std::mutex> lock(mtx_);
    std::auto_ptr<std::thread> new_thread(new std::thread(thread_func));
    threads_.push_back(new_thread.get());
    return new_thread.release();
  }

  void add_thread(std::thread* thd) {
    if (thd) {
      std::lock_guard<std::mutex> lock(mtx_);
      threads_.push_back(thd);
    }
  }

  void remove_thread(std::thread* thd) {
    std::lock_guard<std::mutex> lock(mtx_);
    auto it = std::find(threads_.begin(), threads_.end(), thd);
    if (it != threads_.end()) {
      threads_.erase(it);
    }
  }

  void join_all() {
    std::lock_guard<std::mutex> lock(mtx_);
    for (auto it = threads_.begin(), end = threads_.end(); it != end; ++it) {
      (*it)->join();
    }
  }

  size_t size() const {
    std::lock_guard<std::mutex> lock(mtx_);
    return threads_.size();
  }

 private:
  thread_group(thread_group const&);
  thread_group& operator=(thread_group const&);
 private:
  std::list<std::thread*> threads_;
  mutable std::mutex mtx_;
};

} //!namespace scom

#endif // thread_group_h__

//
// Created by sven on 6/1/17.
//
#ifndef LIBSCOM_MUTUAL_MAP_H
#define LIBSCOM_MUTUAL_MAP_H

#include <unordered_map>
//#define enable_multi_thread
#ifdef enable_multi_thread
#include <mutex>
typedef std::mutex Mutex;
#endif

namespace scom {

template <class _FKey, class _SKey,
    class _FHash = std::hash<_FKey>,
    class _SHash = std::hash<_SKey> >
class mutual_map {
 public:
  mutual_map() {
  }
  ~mutual_map() {
    first_key_m_.clear();
    second_key_m_.clear();
  }

  int insert(_FKey first, _SKey second) {
#ifdef enable_multi_thread
    std::lock_guard<Mutex> lock(mtx_);
#endif
    // insert first map.
    auto iter_f = first_key_m_.find(first);
    if (iter_f != first_key_m_.end()) {
      second_key_m_.erase(iter_f->second);
      iter_f->second = second;
    }
    else {
      first_key_m_.insert(std::make_pair(first, second));
    }
    second_key_m_.insert(std::make_pair(second, first));
    return 0;
  }

  int insert(const std::pair<_FKey, _SKey>& p){
    return insert(p.first, p.second);
  }

  int get_second(const _FKey& first, _SKey* second){
#ifdef enable_multi_thread
    std::lock_guard<Mutex> lock(mtx_);
#endif
    auto iter = first_key_m_.find(first);
    if (iter != first_key_m_.end()) {
      *second = iter->second;
      return 0;
    }
    return -1;
  }

  int get_first(const _SKey& second, _FKey* first) {
#ifdef enable_multi_thread
    std::lock_guard<Mutex> lock(mtx_);
#endif
    auto iter = second_key_m_.find(second);
    if (iter != second_key_m_.end()) {
      *first = iter->second;
      return 0;
    }
    return -1;
  }

  int erase_first(_FKey first) {
#ifdef enable_multi_thread
    std::lock_guard<Mutex> lock(mtx_);
#endif
    auto iter = first_key_m_.find(first);
    if (iter != first_key_m_.end()) {
      second_key_m_.erase(iter->second);
      first_key_m_.erase(iter);
    }
    return 0;
  }

  int erase_second(_SKey second) {
#ifdef enable_multi_thread
    std::lock_guard<Mutex> lock(mtx_);
#endif
    auto iter = second_key_m_.find(second);
    if (iter != second_key_m_.end()) {
      first_key_m_.erase(iter->second);
      second_key_m_.erase(iter);
    }
    return 0;
  }

  bool empty() const {
#ifdef enable_multi_thread
    std::lock_guard<Mutex> lock(mtx_);
#endif
    return first_key_m_.empty();
  }

  size_t size() const {
#ifdef enable_multi_thread
    std::lock_guard<Mutex> lock(mtx_);
#endif
    return first_key_m_.size();
  }

  void clear() {
#ifdef enable_multi_thread
    std::lock_guard<Mutex> lock(mtx_);
#endif
    first_key_m_.clear();
    second_key_m_.clear();
  }

  template <class function>
  int for_each(function fn){
#ifdef enable_multi_thread
    std::lock_guard<Mutex> lock(mtx_);
#endif
    for (auto& iter : first_key_m_){
      fn(iter.first, iter.second);
    }
    return 0;
  }

 private:
  mutual_map(const mutual_map&) = delete;
  const mutual_map& operator=(const mutual_map&) = delete;
 private:
#ifdef enable_multi_thread
  Mutex mtx_;
#endif
  std::unordered_map<_FKey, _SKey, _FHash> first_key_m_;
  std::unordered_map<_SKey, _FKey, _SHash> second_key_m_;
};

} //!namespace scom

#endif //LIBSCOM_MUTUAL_MAP_H

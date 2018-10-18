//
// Created by sven on 5/26/18.
//
#ifndef LIBSCOM_BUFFER_H
#define LIBSCOM_BUFFER_H

#include <string>
#include <cstring>
#include <algorithm>
#include <assert.h>

namespace scom {

class buffer {
public:
  buffer()
    : buf_(nullptr), size_(0), res_(0) {
  }

  buffer(size_t len)
    : buf_((char*)malloc(len))
    , size_(0), res_(len) {
    memset(this->buf_, 0, this->res_);
  }

  buffer(const char* str, size_t len)
    : buf_((char*)malloc(len))
    , size_(len), res_(len) {
    if (str == nullptr) {
      assert(str == nullptr && len == 0);
      return ;
    }
    memcpy(this->buf_, str, this->res_);
  }

  buffer(const std::string& str) 
    : buf_((char*)malloc(str.length()))
    , size_(str.length())
    , res_(str.length()) {
    memset(this->buf_, 0, str.length());
    memcpy(this->buf_, str.data(), str.length());
  }

  buffer(const buffer& buf) {
    this->size_ = buf.size();
    this->res_ = buf.capacity();
    this->buf_ = (char*)malloc(this->res_);
    memcpy(this->buf_, buf.c_str(), this->res_);
  }

  ~buffer() {
    if (this->buf_) {
      free(this->buf_);
      this->buf_ = nullptr;
    }
  }

  buffer& operator=(const buffer& buf) {
    resize(buf.capacity());
    this->size_ = buf.size();
    memcpy(this->buf_, buf.data(), this->res_);
    return *this;
  }

  buffer& operator=(const std::string& str) {
    resize(str.length());
    this->size_ = str.length();
    memcpy(this->buf_, str.data(), str.length());
    return *this;
  }

  buffer& swap(buffer& buf) {
    auto func_swap = [](size_t& a, size_t& b) { a ^= b; b ^= a; a ^= b; };
    func_swap(this->size_, buf.size_);
    func_swap(this->res_, buf.res_);
    char* p = buf.buf_;
    buf.buf_ = this->buf_;
    this->buf_ = p;
    return *this;
  }
  
  int resize(size_t size) {
    if (this->buf_ == nullptr) {
      this->buf_ = (char*)malloc(size);
      this->res_ = size;
      return 0;
    }

    if ((this->buf_ = (char*)realloc(this->buf_, size)) != nullptr) {
      if (size > this->res_)
        memset(this->buf_ + this->res_, 0, size - this->res_);
      this->res_ = size;
      return 0;
    }

    if (size == 0) return 0;
    return -1;
  }

  buffer& assign(const char* str, size_t size) {
    if (str == nullptr || size == 0) {
      return *this;
    }
    if (size > this->res_) resize(size * 2);
    memcpy(this->buf_, str, size);
    this->size_ = size;
    return *this;
  }

  buffer& append(const char* str, size_t size) {
    if (str == nullptr || size == 0) {
      return *this;
    }
    if (size + this->size_ > this->res_)
      resize((std::max)(size + this->size_, size * 2));
    memcpy(this->buf_ + this->size_, str, size);
    this->size_ += size;
    return *this;
  }

  const char* operator[](size_t idx) const {
    if (idx != 0) {
      assert(idx < this->res_);
      if (!this->buf_) return nullptr;
      return this->buf_ + idx;
    }
    return this->buf_;
  }

  char at(size_t idx) const {
    assert(idx < this->res_);
    if (idx >= this->res_ || this->res_ == 0) return '\0';
    return this->buf_[idx];
  }

  buffer& replace(size_t pos, size_t cnt,
                  const char* d_str, size_t d_cnt) {
    assert(pos + cnt <= this->size_);
    if (cnt != d_cnt) {
      if (this->res_ < this->size_ - cnt + d_cnt)
        resize(this->size_ - cnt + d_cnt);
      buffer buf_t(this->buf_ + pos + cnt, this->size_ - pos - cnt);
      memset(this->buf_ + pos, 0, this->size_ - pos);
      memcpy(this->buf_ + pos, d_str, d_cnt);
      memcpy(this->buf_ + pos + d_cnt, buf_t.data(), buf_t.length());
      this->size_ += (d_cnt - cnt);
    }
    else {
      memcpy(this->buf_ + pos, d_str, d_cnt);
    }
    return *this;
  }

  buffer& erase(size_t pos, size_t cnt) {
    assert(pos + cnt <= this->size_);
    memcpy(this->buf_ + pos, this->buf_ + pos + cnt, this->size_ - pos - cnt);
    this->size_ -= cnt;
    memset(this->buf_ + this->size_, 0, cnt);
    return *this;
  }

  const char* c_str() const {
    return this->buf_;
  }

  char* data() {
    return this->buf_;
  }

  const char* data() const {
    return c_str();
  }

  std::string str() const {
    return std::move(std::string(this->buf_, this->size_));
  }

  size_t size() const {
    return this->size_;
  }

  size_t length() const {
    return size();
  }

  size_t capacity() const {
    return this->res_;
  }

  bool empty() const {
    return (this->size_ == 0);
  }

  void clear() {
    memset(buf_, 0, res_);
    size_ = 0;
  }

private:
  char* buf_;
  size_t size_; // size
  size_t res_; // capacity
};

}//!namespace scom

#endif // LIBSCOM_BUFFER_H
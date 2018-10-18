//
// Created by sven on 6/1/17.
//

#ifndef LIBSCOM_NONCOPYABLE_H
#define LIBSCOM_NONCOPYABLE_H

namespace scom {

class noncopyable {
 protected:
  noncopyable() {}
  virtual ~noncopyable() {}
 private:
  // emphasize the following members are private
  noncopyable(const noncopyable&) = delete;
  const noncopyable& operator=(const noncopyable&) = delete;
};

}//!namespace scom

#endif //LIBSCOM_NONCOPYABLE_H

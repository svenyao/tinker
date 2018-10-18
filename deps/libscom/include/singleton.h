//
// Created by sven on 6/1/17.
//

#ifndef LIBSCOM_SINGLETON_H
#define LIBSCOM_SINGLETON_H

#include "noncopyable.h"

namespace scom {

template<typename T>
class singleton : public noncopyable {
 public:
  static T& instance() { //it's thread-safe in c++11
    static T t;
    return t;
  }
};

}//!namespace scom

#endif //LIBSCOM_SINGLETON_H

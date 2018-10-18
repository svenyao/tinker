//
// Created by sven on 6/4/17.
//

#ifndef LIBSCOM_LEXICAL_CAST_H
#define LIBSCOM_LEXICAL_CAST_H

#include <sstream>
#include <typeinfo>
#include <cstring>
#include <stdexcept>

namespace scom {

class bad_lexical_cast : public std::bad_cast {
 public:
  bad_lexical_cast() :
      source(&typeid(void)), target(&typeid(void)) {
  }

  bad_lexical_cast(const std::type_info &source_type_arg,
                   const std::type_info &target_type_arg) :
      source(&source_type_arg), target(&target_type_arg) {
  }

  const std::type_info &source_type() const {
    return *source;
  }
  const std::type_info &target_type() const {
    return *target;
  }

  virtual const char *what() const throw() {
    return "bad lexical cast: "
        "source type value could not be interpreted as target";
  }
  virtual ~bad_lexical_cast() throw() {
  }
 private:
  const std::type_info *source;
  const std::type_info *target;
};

namespace detail {

const std::string str_true = "true";
const std::string str_false = "false";

template<typename Target, typename Source>
struct Converter {
  static Target convert(const Source &arg, const bool bthrow) {
    std::stringstream interpreter;
    interpreter.setf(std::ios::fixed);
    Target result;

    if (!(interpreter << arg && interpreter >> result) && bthrow)
      throw bad_lexical_cast(typeid(Source), typeid(Target));

    return result;
  }
};

// support string
template<>
struct Converter<std::string, std::string> {
  static std::string convert(const std::string &source, const bool bthrow = false) {
    return source;
  }
};

template<>
struct Converter<std::string, const char*> {
  static std::string convert(const char* source, const bool bthrow = false) {
    return std::move(std::string(source));
  }
};

template<>
struct Converter<std::string, char*> {
  static std::string convert(char* source, const bool bthrow = false) {
    return std::move(std::string(source));
  }
};

// support bool
template<typename Source>
struct Converter<bool, Source> {
  static bool convert(const Source &arg, const bool bthrow) {
    return !!arg;
  }
};

inline bool convert(const char *from, const bool bthrow) {
  const unsigned int len = strlen(from);
  if (len != 4 && len != 5 && bthrow)
    throw std::invalid_argument("argument is invalid");

  if (len == 4) {
    if (!str_true.compare(from))
      return true;
  } else if (len == 5) {
    if (!str_false.compare(from))
      return false;
  }
  if (bthrow)
    throw std::invalid_argument("argument is invalid");
  else
    return false;
}

template<>
struct Converter<bool, std::string> {
  static bool convert(const std::string &source, const bool bthrow = false) {
    return detail::convert(source.c_str(), bthrow);
  }
};

template<>
struct Converter<bool, const char *> {
  static bool convert(const char *source, const bool bthrow = false) {
    return detail::convert(source, bthrow);
  }
};

template<>
struct Converter<bool, char *> {
  static bool convert(char *source, const bool bthrow = false) {
    return detail::convert(source, bthrow);
  }
};

template<unsigned N>
struct Converter<bool, const char[N]> {
  static bool convert(const char (&source)[N], const bool bthrow = false) {
    return detail::convert(source, bthrow);
  }
};

template<unsigned N>
struct Converter<bool, char[N]> {
  static bool convert(const char (&source)[N], const bool bthrow = false) {
    return detail::convert(source, bthrow);
  }
};

template<typename Source>
struct Converter <unsigned char, Source> {
  static unsigned char convert(const Source &arg, const bool bthrow) {
    std::stringstream interpreter;
    interpreter.setf(std::ios::fixed);
    unsigned short result;

    if (!(interpreter << arg && interpreter >> result) && bthrow)
      throw bad_lexical_cast(typeid(Source), typeid(unsigned short));

    return static_cast<unsigned char>(result);
  }
};

template<typename Source>
struct Converter <signed char, Source> {
  static signed char convert(const Source &arg, const bool bthrow) {
    std::stringstream interpreter;
    interpreter.setf(std::ios::fixed);
    short result;

    if (!(interpreter << arg && interpreter >> result) && bthrow)
      throw bad_lexical_cast(typeid(Source), typeid(short));

    return static_cast<signed char>(result);
  }
};

}//!namespace detail

template<typename Target, typename Source>
Target lexical_cast(const Source &arg, const bool bthrow = false) {
  return detail::Converter<Target, Source>::convert(arg, bthrow);
}

}//namespace scom.

#endif //LIBSCOM_LEXICAL_CAST_H

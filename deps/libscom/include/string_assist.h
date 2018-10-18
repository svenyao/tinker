//
// Created by sven on 6/1/17.
//

#ifndef LIBSCOM_STRING_ASSIST_H
#define LIBSCOM_STRING_ASSIST_H

#include <string>
#include <algorithm>
#include <cstring>
#include <memory>
#ifdef _WIN32
#include <vector>
#include <functional>
#include <cctype>
#include <winsock2.h>
#include <windows.h>
#endif

namespace scom {

class string_assist {
 public:
  static std::string& replace(
      std::string& str, const std::string& old_val, const std::string& new_val){
    for(std::string::size_type pos(0); pos != std::string::npos; pos += new_val.length()) {
      if( (pos = str.find(old_val,pos)) != std::string::npos )
        str.replace(pos, old_val.length(), new_val);
      else
        break;
    }
    return str;
  }

  static int split(const std::string& str, const std::string& sepr,
                   std::vector<std::string>& elems) {
    elems.clear();
    size_t last = 0;
    size_t index = str.find_first_of(sepr, last);
    while (index != std::string::npos) {
      elems.emplace_back(str.substr(last, index - last));
      last = index + sepr.size();
      index = str.find_first_of(sepr, last);
    }
    if (index - last > 0) {
      elems.emplace_back(str.substr(last, index - last));
    }
    return 0;
  }

  static std::string& to_upper(std::string &str) {
    std::transform(str.begin(), str.end(), str.begin(), (int (*)(int))toupper);
    return str;
  }

  static std::string& to_lower(std::string &str) {
    std::transform(str.begin(), str.end(), str.begin(), (int (*)(int))tolower);
    return str;
  }

  // trim
  // ltrim, rtrim, trim
  static std::string &ltrim(std::string &str) {
    str.erase(str.begin(), std::find_if(str.begin(), str.end(),
                                        std::not1(std::ptr_fun<int, int>(std::isspace))));
    return str;
  }
  static std::string &rtrim(std::string &str) {
    str.erase(std::find_if(str.rbegin(), str.rend(),
                           std::not1(std::ptr_fun<int, int>(std::isspace))).base(),
              str.end());
    return str;
  }
  static std::string &trim(std::string &str) {
    return ltrim(rtrim(str));
  }

  //
  // to hex
  static std::string to_hex(const std::string& str) {
    static const char hex_chars[] = "0123456789abcdef";
    std::string ret;
    for (std::string::const_iterator i = str.begin(); i != str.end(); ++i) {
      ret += hex_chars[((unsigned char)*i) >> 4];
      ret += hex_chars[((unsigned char)*i) & 0xf];
    }
    return std::move(ret);
  }
  // hex to bin
  static std::string hex2bin(const std::string& stx) {
    if (stx.length() % 2 != 0) return std::string();
    static const char hex_chars[] = "0123456789abcdef";
    std::string ret;
    unsigned int n1 = 0,n2 = 0;
    for (std::string::const_iterator i = stx.begin(); i != stx.end(); i=i+2) {
      for (unsigned int j = 0; j < sizeof(hex_chars); ++j) {
        if (*i == hex_chars[j]) {
          n1 = j;
        }
        if (*(i+1) == hex_chars[j]) {
          n2 = j;
        }
      }
      ret += ((unsigned char)n1 << 4) | ((unsigned char)n2);
    }
    return std::move(ret);
  }

  // remove comment <support c/c++/json/js...>
  static std::string remove_comment(const std::string& content) {
    std::string output;
    uint8_t fsm[9][128];
    init_fsm(fsm);
    uint8_t status = 0;
    std::string temp_str;
    for(size_t idx = 0; idx < content.length(); ++idx){
      char c = content.at(idx);
      uint8_t c_t = (c >= 0 && c < 127) ? c : 127;
      status = fsm[status][c_t];
      temp_str += c;
      switch (status){
        case 0:
          output.append(temp_str);
          temp_str = "";
          break;
        case 8:
          temp_str = "";
          break;
        default:
          break;
      }
    }
    return output;
  }

#ifndef _WIN32
  static std::wstring s2ws(const std::string& str) {
    if (str.empty()) return L"";
    unsigned long len = str.size() + 1;
    std::string curLocale = setlocale(LC_ALL, NULL);
    setlocale(LC_CTYPE, "en_US.UTF-8");
    std::unique_ptr<wchar_t[]> p(new wchar_t[len]);
    mbstowcs(p.get(), str.c_str(), len);
    std::wstring w_str(p.get());
    setlocale(LC_ALL, curLocale.c_str());
    return w_str;
  }

  static std::string ws2s(const std::wstring& w_str) {
    if (w_str.empty()) return "";
    unsigned long len = w_str.size() * sizeof(wchar_t) + 1;
    std::string curLocale = setlocale(LC_ALL, NULL);
    setlocale(LC_CTYPE, "en_US.UTF-8");
    std::unique_ptr<char[]> p(new char[len]);
    wcstombs(p.get(), w_str.c_str(), len);
    std::string str(p.get());
    setlocale(LC_ALL, curLocale.c_str());
    return str;
  }

#else
  static std::wstring ansi_to_unicode(const std::string& sz_ansi) {
    int wcslen = ::MultiByteToWideChar(CP_ACP, NULL, sz_ansi.c_str(), sz_ansi.length(), NULL, 0);
    wchar_t* sz_unicode = new wchar_t[wcslen + 1];
    ::MultiByteToWideChar(CP_ACP, NULL, sz_ansi.c_str(), sz_ansi.length(), sz_unicode, wcslen);
    sz_unicode[wcslen] = '\0';
    std::wstring unicode_str = sz_unicode;
    delete[] sz_unicode;
    return unicode_str;
  }

  static std::string	unicode_to_ansi(const std::wstring& sz_unicode) {
    int ansilen = ::WideCharToMultiByte(CP_ACP, NULL, sz_unicode.c_str(), sz_unicode.length(), NULL, 0, NULL, NULL);
    char* sz_ansi = new char[ansilen + 1];
    ::WideCharToMultiByte(CP_ACP, NULL, sz_unicode.c_str(), sz_unicode.length(), sz_ansi, ansilen, NULL, NULL);
    sz_ansi[ansilen] = '\0';
    std::string ansi_str = sz_ansi;
    delete[] sz_ansi;
    return ansi_str;
  }

  static std::wstring utf8_to_unicode(const std::string& sz_utf) {
    int wcslen = ::MultiByteToWideChar(CP_UTF8, NULL, sz_utf.c_str(), sz_utf.length(), NULL, 0);
    wchar_t* sz_unicode = new wchar_t[wcslen + 1];
    ::MultiByteToWideChar(CP_UTF8, NULL, sz_utf.c_str(), sz_utf.length(), sz_unicode, wcslen);
    sz_unicode[wcslen] = '\0';
    std::wstring unicode_str = sz_unicode;
    delete[] sz_unicode;
    return unicode_str;
  }

  static std::string unicode_to_utf8(const std::wstring& sz_unicode) {
    int u8len = ::WideCharToMultiByte(CP_UTF8, NULL, sz_unicode.c_str(), sz_unicode.length(), NULL, 0, NULL, NULL);
    char* sz_utf8 = new char[u8len + 1];
    ::WideCharToMultiByte(CP_UTF8, NULL, sz_unicode.c_str(), sz_unicode.length(), sz_utf8, u8len, NULL, NULL);
    sz_utf8[u8len] = '\0';
    std::string utf8_str = sz_utf8;
    delete[] sz_utf8;
    return utf8_str;
  }
#endif

 private:
  static void init_fsm(uint8_t fsm[9][128]){
    const uint32_t cols=sizeof(uint8_t)*128;
    memset(fsm[0],0,cols);
    memset(fsm[1],0,cols);
    memset(fsm[2],2,cols);
    memset(fsm[3],3,cols);
    memset(fsm[4],3,cols);
    memset(fsm[5],5,cols);
    memset(fsm[6],5,cols);
    memset(fsm[7],0,cols);
    memset(fsm[8],0,cols);

    fsm[0]['/'] = 1;
    fsm[0]['"'] = 5;
    fsm[0]['\\'] = 7;
    fsm[1]['/'] = 2;
    fsm[1]['*'] = 3;
    fsm[1]['"'] = 5;
    fsm[2]['\n'] = 8;
    fsm[3]['*'] = 4;
    fsm[4]['/'] = 8;
    fsm[4]['*'] = 4;
    fsm[5]['"'] = 0;
    fsm[5]['\\'] = 6;
    fsm[8]['/'] = 1;
    fsm[8]['"'] = 5;
    fsm[8]['\\'] = 7;
  }
};

}//!namespace scom

#endif //LIBSCOM_STRING_ASSIST_H

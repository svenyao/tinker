//
// Created by sven on 6/2/17.
//

#ifndef LIBSCOM_DIRECT_ASSIST_H
#define LIBSCOM_DIRECT_ASSIST_H

#include "string_assist.h"
#ifdef _WIN32
#include <winsock2.h>
#include <windows.h>
#include <ShlObj.h>
#include <direct.h>
#include <io.h>
#else
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>
#endif

#ifdef _WIN32
#define ACCESS _access
#define MKDIR(a) _mkdir((a))
#else
#define ACCESS access
#define MKDIR(a) mkdir((a),0755)
#endif

namespace scom {

class direct_assist {
 public:
  static std::string getcwd_t() {
    char fullpath[260];
#ifdef _WIN32
    _getcwd(fullpath, sizeof(fullpath));
#else
    getcwd(fullpath, sizeof(fullpath));
#endif
    return std::string(fullpath);
  }

  static bool access_file(const std::string& file_path, int mode) {
    if (ACCESS(file_path.c_str(), mode) == 0) {
      return true;
    }
    else {
      return false;
    }
  }

  // 多层目录结构的创建
  static int create_direct(const std::string& direct_path) {
    std::string path_str = direct_path;
    path_str = string_assist::replace(path_str, "\\", "/");
    int nlen = direct_path.length();
    // 为兼容linux目录以'/'起，此处索引从1开始计算。
    for (int idx = 1; idx < nlen; ++idx) {
      if (path_str.at(idx) == '/') {
        std::string path_t = path_str.substr(0, idx);
        if (ACCESS(path_t.c_str(), 0) != 0) {
          if (MKDIR(path_t.c_str()) != 0) {
            return -1;
          }
        }
      }
    }
    if (ACCESS(path_str.c_str(), 0) != 0) {
      if (MKDIR(path_str.c_str()) != 0) {
        return -1;
      }
    }

    return 0;
  }

  //remove direct
  static int remove_direct( const std::string& direct_path ) {
#ifdef _WIN32
    return _rmdir(direct_path.c_str());
#else
    return rmdir(direct_path.c_str());
#endif
  }

  // remove file
  static int remove_file( const std::string& file_path ) {
    return remove(file_path.c_str());
  }
};

}//!namespace scom

#endif //LIBSCOM_DIRECT_ASSIST_H

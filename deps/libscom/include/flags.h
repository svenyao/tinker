//
// Created by sven on 9/16/18.
//

#ifndef LIBSCOM_FLAGS_H
#define LIBSCOM_FLAGS_H
#include "string_assist.h"
#include "lexical_cast.h"
#include <unordered_map>
#include <iostream>
#include <fstream>

namespace scom {

class flags {
  struct opt_define {
    std::string opt_name;
    std::string opt_abbr;
    std::string opt_default;
    std::string comments;
    bool single_opt;  // single option does not have args value.
  };
 public:
  // @param fok is true, when option not defined, it not exit.
  explicit flags(bool fok = false)
      : def_version_(false), fok_(fok) {
    initialize();
  }

  // @param version assign application version.
  // @param fok is true, when option not defined, it not exit.
  explicit flags(const std::string& version, bool fok = false)
    : def_version_(false), fok_(fok) {
    initialize();
    set_version(version);
    def_opt("help", 'h', "", "show help text and quit", true);
  }

  // @param version assign application version.
  // @param fok is true, when option not defined, it not exit.
  explicit flags(const char* version, bool fok = false)
      : def_version_(false), fok_(fok) {
    initialize();
    set_version(std::string(version));
    def_opt("help", 'h', "", "show help text and quit", true);
  }

  // @param app_name assign application name.
  // @param version assign application version.
  // @param fok is true, when option not defined, it not exit.
  explicit flags(const std::string& app_name, const std::string& version, bool fok = false)
    : app_name_(app_name), def_version_(false), fok_(fok) {
    initialize();
    set_version(version);
    def_opt("help", 'h', "", "show help text and quit", true);
  }

  // @param version assign application version.
  void set_version(const std::string& version) {
    if (!version.empty()) {
      def_version_ = true;
      if (app_name_.empty()) app_name_ = "app_name";
      def_opt("version", 'v', version, "show version number and quit", true);
    }
  }

  // parse from argc and argv (for main(argc, argv))
  int parse(int argc, char** argv) {
    opt_map_.clear();
    for (size_t idx = 0; idx < (size_t)argc; ++idx) {
      if (idx == 0 && argv[0][0] != '-') {
        if (app_name_.empty() || app_name_.compare("app_name") == 0)
          app_name_ = get_app_name(argv[0]);
        def_opt("help", 'h', "", "show help text and quit", true);
        continue;
      }
      if (parser(argv[idx]) != 0) {
        if (!app_name_.empty()) show_failed(argv[idx]);
        return -1;
      }
    }
    if (opt_map_.size() == 1 && found_opt("flag_file")) {
      return parse_file(get_opt<std::string>("flag_file"));
    }
    return 0;
  }

  // parse from string
  int parse(const std::string& args) {
    opt_map_.clear();
    std::vector<std::string> arg_arr;
    scom::string_assist::split(args, " ", arg_arr);
    size_t idx = 0;
    for (auto& iter : arg_arr) {
      scom::string_assist::trim(iter);
      if (iter.empty()) continue;
      if (idx == 0 && iter.at(0) != '-') {
        if (app_name_.empty() || app_name_.compare("app_name") == 0)
          app_name_ = get_app_name(iter);
        def_opt("help", 'h', "", "show help text and quit", true);
        continue;
      }
      ++idx;
      if (parser(iter) != 0) {
        if (!app_name_.empty()) show_failed(iter);
        return -1;
      }
    }
    return 0;
  }

  // parse from file (for --flag_file )
  int parse_file(const std::string& path) {
    std::ifstream ifs(path, std::ios::binary);
    std::ostringstream oss;
    oss << ifs.rdbuf();
    std::string args = oss.str();
    scom::string_assist::remove_comment(args);
    scom::string_assist::replace(args, "\r", "");
    scom::string_assist::replace(args, "\n", " ");
    scom::string_assist::replace(args, "\t", " ");
    return parse(args);
  }

  // get option value, when not defined get default value.
  template <class T>
  int get_opt(const std::string& opt, T& val) {
    std::string opt_name = get_opt_name(opt);
    auto iter_o = opt_map_.find(opt_name);
    if (iter_o != opt_map_.end()) {
      val = lexical_cast<T>(iter_o->second);
      return 0;
    }
    auto iter_def = opt_def_map_.find(opt_name);
    if (iter_def != opt_def_map_.end()) {
      return lexical_cast<T>(iter_def->second->opt_default);
    }
    return -1;
  }

  // get option value, when not defined get default value.
  template <class T>
  T get_opt(const std::string& opt) {
    std::string opt_name = get_opt_name(opt);
    auto iter_o = opt_map_.find(opt_name);
    if (iter_o != opt_map_.end()) {
      return lexical_cast<T>(iter_o->second);
    }
    auto iter_def = opt_def_map_.find(opt_name);
    if (iter_def != opt_def_map_.end()) {
      return lexical_cast<T>(iter_def->second->opt_default);
    }
    return lexical_cast<T>("");
  }

  // judge this option is existed, existed return true.
  bool found_opt(const std::string& opt) {
    std::string opt_name = get_opt_name(opt);
    return (opt_map_.find(opt_name) != opt_map_.end());
  }

  // universal define option
  template <class T>
  int def_opt(const std::string& opt_name, const unsigned char& opt_abbr,
    const T& opt_default, const std::string& comments, bool single_opt = false) {
    std::shared_ptr<opt_define> def_pt = std::make_shared<opt_define>();
    def_pt->opt_name = opt_name;
    if (opt_abbr != ' ' && opt_abbr != 0)
      def_pt->opt_abbr = std::string(1, opt_abbr);
    def_pt->opt_default = lexical_cast<std::string>(opt_default);
    def_pt->comments = comments;
    def_pt->single_opt = single_opt;

    if (!def_pt->opt_abbr.empty()) {
      auto iter = opt_abbr_map_.find(def_pt->opt_abbr);
      if (iter != opt_abbr_map_.end()) return -1;
      opt_abbr_map_.insert(std::make_pair(def_pt->opt_abbr, opt_name));
    }
    {
      auto iter = opt_def_map_.find(opt_name);
      if (iter != opt_def_map_.end()) return -2;
      opt_def_map_.insert(std::make_pair(opt_name, def_pt));
    }
    return 0;
  }

  // define single option
  // single option does not have args value.
  int def_opt(const std::string& opt_name, const unsigned char& opt_abbr,
              const std::string& comments) {
    return this->def_opt(opt_name, opt_abbr, "", comments, true);
  }

  // clear all option
  void clear() {
    opt_map_.clear();
    opt_abbr_map_.clear();
    opt_def_map_.clear();
  }
 private:
  uint8_t fsm[8][3];
  std::unordered_map<std::string, std::string> opt_map_;
  std::unordered_map<std::string, std::string> opt_abbr_map_;
  std::unordered_map<std::string, std::shared_ptr<opt_define>> opt_def_map_;

  std::string app_name_;
  bool def_version_;
  bool fok_;

  void initialize() {
    init_fsm(fsm);
    opt_map_.clear();
    opt_abbr_map_.clear();
    opt_def_map_.clear();
  }
  //
  int init_fsm(uint8_t fsm[8][3]) {
    memset(fsm, 7, sizeof(uint8_t) * 8 * 3);

    fsm[0][0] = 1;
    fsm[1][0] = 2;
    fsm[1][1] = 3;
    fsm[2][1] = 4;
    fsm[3][0] = 3;
    fsm[3][1] = 3;
    fsm[3][2] = 5;
    fsm[4][0] = 4;
    fsm[4][1] = 4;
    fsm[4][2] = 5;
    fsm[5][1] = 6;
    fsm[6][0] = 6;
    fsm[6][1] = 6;
    return 0;
  }

  int parser(const std::string& content) {
    uint8_t status = 0;
    bool key_abbr = false;
    std::string key;
    std::string value;
    for (size_t idx = 0; idx < content.length(); ++idx) {
      char c = content.at(idx);
      uint8_t c_y = get_dimension_y(c);
      if (c_y == 4) return -1;

      status = fsm[status][c_y];
      switch (status) {
        case 3:
          key_abbr = true;
          key += c;
          break;
        case 4:
          key += c;
          break;
        case 6:
          value += c;
          break;
        case 7:
          return -1;
        default:
          break;
      }
    }

    if (key_abbr) {
      auto iter = opt_abbr_map_.find(key);
      if (iter == opt_abbr_map_.end())
        return -1;
      key = iter->second;
    }
    else {
      auto iter = opt_abbr_map_.find(key);
      if (iter != opt_abbr_map_.end())
        return -1;
    }

    auto iter = opt_def_map_.find(key);
    if (iter != opt_def_map_.end()) {
      if (status == 3 || status == 4) {
        if (!iter->second->single_opt) return -1;
        value = iter->second->opt_default;
      }
      else if (status == 6) {
        if (iter->second->single_opt) return -1;
      }
    }
    else {
      if (!fok_ && key.compare("flag_file") != 0)
        return -1;
      if (status == 3 || status == 4) {
        value = "true";
      }
    }

    if (!app_name_.empty() && (status == 3 || status == 4)) {
      if (def_version_ && key.compare("version") == 0) {
        show_version();
      }
      else if (key.compare("help") == 0) {
        show_help();
      }
    }

    if (status == 3 || status == 4 || status == 6) {
      opt_map_.insert(std::make_pair(key, value));
    }
    else {
      return -1;
    }

    return 0;
  }

  uint8_t get_dimension_y(char c) {
    if (c == '-') return 0;
    else if (c > 32 && c < 127 && c != '=') return 1;
    else if (c == '=') return 2;
    else return 4;
  }
  
  std::string get_opt_name(const std::string& opt) {
    auto iter = opt_abbr_map_.find(opt);
    if (iter != opt_abbr_map_.end()) return iter->second;
    return opt;
  }

  void show_version() {
    std::string v = get_opt<std::string>("version");
    if (!v.empty()) {
      std::cout << app_name_ << " version: " << v << std::endl;
    }
    exit(0);
  }

  void show_help() {
    std::string v = get_opt<std::string>("version");
    if (!v.empty()) {
      std::cout << app_name_ << " version: " << v << std::endl;
    }
    std::cout << "Usage: " << app_name_ << " [options...]" << std::endl;
    std::cout << "Options: " << std::endl;
    for (auto iter : opt_def_map_) {
      if (!iter.second->opt_abbr.empty())
        std::cout << " -" << iter.second->opt_abbr << ", ";
      else
        std::cout << "     ";
      std::cout << "--" << iter.second->opt_name << "\t";
      if (!iter.second->single_opt)
        std::cout << "<v> ";
      else
        std::cout << "<s> ";
      std::cout << iter.second->comments << std::endl;
    }
    exit(0);
  }

  void show_failed(const std::string& args) {
    std::cerr << app_name_ << (app_name_.empty()?"":": ")<< "invalid option '" << args << "'" << std::endl;
    std::cerr << "try '" << app_name_ << " --help' for more information." << std::endl;
    exit(0);
  }

  std::string get_app_name(const std::string& str) {
    std::string new_str = str;
    for (size_t idx = str.length(); idx > 0; --idx) {
      if (str.at(idx - 1) == '/' || str.at(idx - 1) == '\\') {
        new_str = str.substr(idx, str.length() - idx);
        break;
      }
    }
#ifdef _WIN32
    if (new_str.length() > 4 && new_str.substr(new_str.length()-4, 4).compare(".exe") == 0) {
      new_str = new_str.substr(0, new_str.length() - 4);
    }
#endif
    return std::move(new_str);
  }
};

}//!namespace scom

#endif //LIBSCOM_FLAGS_H

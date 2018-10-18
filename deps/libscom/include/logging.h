//
// Created by sven on 6/1/17.
//

#ifndef LIBSCOM_LOGGING_H
#define LIBSCOM_LOGGING_H

#include "direct_assist.h"
#include "singleton.h"
#include "spdlog/spdlog.h"
#include <iostream>

namespace scom {

class logging : public singleton<logging> {
 public:
  logging() : verbose_(0), logger_name_("console") {
    try {
      if (!spdlog::get(logger_name_)) {
        app_log_ = spdlog::stdout_color_mt(logger_name_);
        set_patten("[%Y-%m-%d %X.%e] [%l] %v");
        set_level(2);
        set_async_mode(1<<16, true);
      }
      else {
        app_log_ = spdlog::get(logger_name_);
      }
    }
    catch (const spdlog::spdlog_ex& ex) {
      std::cout << "logging exception: " << ex.what() << std::endl;
    }
  }

  ~logging() {
    spdlog::drop_all();
  }

  void set_verbose(unsigned int v) {
    verbose_ = v;
  }

  void set_level(unsigned int lev) {
    try {
      spdlog::set_level(spdlog::level::level_enum(lev));
    }
    catch (const spdlog::spdlog_ex& ex) {
      std::cout << "logging exception: " << ex.what() << std::endl;
    }
  }

  void set_patten(const std::string& pattern) {
    try {
      spdlog::set_pattern(pattern);
    }
    catch (const spdlog::spdlog_ex& ex) {
      std::cout << "logging exception: " << ex.what() << std::endl;
    }
  }
  // @param block true is block message, false is discard message.
  void set_async_mode(size_t queue_size, bool block = true, size_t flush_s = 1) {
    try {
      size_t q_size = (queue_size / 2) * 2;
      if (block) {
        spdlog::set_async_mode(q_size, spdlog::async_overflow_policy::block_retry,
                               nullptr, std::chrono::seconds(flush_s));
      }
      else {
        spdlog::set_async_mode(q_size, spdlog::async_overflow_policy::discard_log_msg,
                               nullptr, std::chrono::seconds(flush_s));
      }
    }
    catch (const spdlog::spdlog_ex& ex) {
      std::cout << "logging exception: " << ex.what() << std::endl;
    }
  }

  int create(const std::string &app_name, const std::string &log_dir,
             const std::string &logger_name = "default", bool mtx_enable = true) {
    if (log_dir.empty()) {
      return -1;
    }

    if (direct_assist::create_direct(log_dir) != 0) {
      app_log_->error("create log dir error: {} ", log_dir);
    }

    std::string log_dir_t = log_dir;
    log_dir_t.append("/").append(app_name);
    try {
      if (!mtx_enable) {
        if (app_log_->name() != logger_name_) {
          spdlog::daily_logger_st(logger_name, log_dir_t, 23, 59);
        }
        else {
          app_log_ = spdlog::daily_logger_st(logger_name, log_dir_t, 23, 59);
        }
      }
      else {
        if (app_log_->name() != logger_name_) {
          spdlog::daily_logger_mt(logger_name, log_dir_t, 23, 59);
        }
        else {
          app_log_ = spdlog::daily_logger_mt(logger_name, log_dir_t, 23, 59);
        }
      }
      spdlog::get(logger_name)->flush_on(spdlog::level::err);
    }
    catch (const spdlog::spdlog_ex& ex) {
      std::cout << "logging exception: " << ex.what() << std::endl;
    }

    return 0;
  }

  unsigned int get_verbose() {
    return verbose_;
  }

  std::shared_ptr<spdlog::logger> get_logger(const std::string& logger_name = "") {
    if (!logger_name.empty()) {
      return ((spdlog::get(logger_name) ? spdlog::get(logger_name) : app_log_));
    }
    return app_log_;
  }
 private:
  std::shared_ptr<spdlog::logger> app_log_;
  unsigned int verbose_;
  std::string logger_name_;
};

}//!namespace scom

#define LOG(level, ...) scom::logging::instance().get_logger()->level(__VA_ARGS__)
#define VLOG(v, ...)  (v) > scom::logging::instance().get_verbose() ? void(0) : \
  scom::logging::instance().get_logger()->info(__VA_ARGS__)

#define DLOG(name, level, ...) scom::logging::instance().get_logger(name)->level(__VA_ARGS__)
#define VDLOG(name, v, ...)  (v) > scom::logging::instance().get_verbose() ? void(0) : \
  scom::logging::instance().get_logger(name)->info(__VA_ARGS__)

#endif //LIBSCOM_LOGGING_H

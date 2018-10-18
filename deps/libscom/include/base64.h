//
// Created by sven on 6/1/17.
//

#ifndef LIBSCOM_BASE64_H
#define LIBSCOM_BASE64_H
#include "string_assist.h"

namespace scom {

class base64 {
 public:
  static int encode(const std::string& input, std::string& output, bool with_new_line = false);
  static int decode(const std::string& input, std::string& output, bool with_new_line = false);
};

static const char encode_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
static const int decode_chars[] = {
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, 62, -1, -1, -1, 63,
    52, 53, 54, 55, 56, 57, 58, 59, 60, 61, -1, -1, -1, -1, -1, -1,
    -1, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
    15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, -1, -1, -1, -1, -1,
    -1, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
    41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51, -1, -1, -1, -1, -1 };
static const size_t line_size = 72;

inline int base64::encode(const std::string& input, std::string& output, bool with_new_line) {
  std::string out_str;
  unsigned int i, len;
  int c1, c2, c3;

  len = input.length();
  i = 0;
  out_str.clear();
  while (i < len) {
    c1 = input[i++] & 0xff;
    if (i == len) {
      out_str += encode_chars[(c1 >> 2)];
      out_str += encode_chars[((c1 & 0x3) << 4)];
      out_str += "==";
      break;
    }
    c2 = input[(i++)];
    if (i == len) {
      out_str += encode_chars[(c1 >> 2)];
      out_str += encode_chars[((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4)];
      out_str += encode_chars[((c2 & 0xF) << 2)];
      out_str += "=";
      break;
    }
    c3 = input[(i++)];
    out_str += encode_chars[(c1 >> 2)];
    out_str += encode_chars[(((c1 & 0x3) << 4) | ((c2 & 0xF0) >> 4))];
    out_str += encode_chars[(((c2 & 0xF) << 2) | ((c3 & 0xC0) >> 6))];
    out_str += encode_chars[(c3 & 0x3F)];
  }

  if (!with_new_line) {
    output = std::move(out_str);
  }
  else {
    output.clear();
    for (size_t idx = 0; idx < out_str.length(); idx += line_size) {
      if (!output.empty()) output.append("\r\n");
      output.append(out_str.substr(idx, std::min(line_size, out_str.length() - idx)));
    }
  }
  return 0;
}

inline int base64::decode(const std::string& input, std::string& output, bool with_new_line) {
  int c1, c2, c3, c4;
  unsigned int i, len;
  std::string in_str = std::move(input);
  if (with_new_line) {
    in_str = string_assist::replace(in_str, "\r\n", "");
  }

  len = in_str.length();
  i = 0;
  output.clear();
  while (i < len) {
    /* c1 */
    do {
      c1 = decode_chars[in_str[(i++)] & 0xff];
    } while (i < len && c1 == -1);
    if (c1 == -1)
      break;

    /* c2 */
    do {
      c2 = decode_chars[in_str[(i++)] & 0xff];
    } while (i < len && c2 == -1);
    if (c2 == -1)
      break;

    output += (char)((c1 << 2) | ((c2 & 0x30) >> 4));

    /* c3 */
    do {
      c3 = in_str[(i++)] & 0xff;
      if (c3 == 61)
        return 0;
      c3 = decode_chars[c3];
    } while (i < len && c3 == -1);
    if (c3 == -1)
      break;

    output += (char)(((c2 & 0xF) << 4) | ((c3 & 0x3C) >> 2));

    /* c4 */
    do {
      c4 = in_str[(i++)] & 0xff;
      if (c4 == 61)
        return 0;
      c4 = decode_chars[c4];
    } while (i < len && c4 == -1);
    if (c4 == -1)
      break;
    output += (char)(((c3 & 0x03) << 6) | c4);
  }
  return 0;
}

} //!namespace scom

#endif //LIBSCOM_BASE64_H
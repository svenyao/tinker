//
// Created by sven on 9/2/18.
//

#include "unique_id.h"
#include "logging.h"
#include "base64.h"

int main(int argc, char** argv) {
#if 0
  scom::unique_id uuid;
  for (auto idx = 0; idx < 10; ++idx) {
    LOG(info, "{}:[{}]", idx+1, uuid.generate());
  }
#endif

  LOG(warn, "test base64 encode ============== ");
  std::string input = "scom::unique_id uuid;\n"
      "for (auto idx = 0; idx < 10; ++idx) {\n"
      "  LOG(info, \"{}:[{}]\", idx+1, uuid.generate());\n"
      "}\ntest base64 encode ============== ";
  std::string output;
  std::string output2;

  scom::base64::encode(input, output);
  LOG(info, "output:\r\n{}", output);
  scom::base64::decode(output, output2);
  LOG(info, "output2:\r\n{}", output2);

  scom::base64::encode(input, output, true);
  LOG(info, "output:\r\n{}", output);
  scom::base64::decode(output, output2, true);
  LOG(info, "output2:\r\n{}", output2);

  return 0;
}
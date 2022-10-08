#include "FuzzedDataProvider.h"
#include "cwalk.h"

#define noop

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
  FuzzedDataProvider fdp(data, size);
  const char *base_name;
  size_t length;
  std::string p1 = fdp.ConsumeRandomLengthString();
  cwk_path_get_basename(p1.c_str(), &base_name, &length);

  // Directory Test
  std::string p2 = fdp.ConsumeRandomLengthString();
  cwk_path_get_dirname(p2.c_str(), &length);

  // Root Test
  std::string p3 = fdp.ConsumeRandomLengthString();
  cwk_path_get_root(p3.c_str(), &length);

  // Absolute or relative
  std::string p4 = fdp.ConsumeRandomLengthString();
  cwk_path_is_absolute(p4.c_str());
  std::string p5 = fdp.ConsumeRandomLengthString();
  cwk_path_is_relative(p5.c_str());

  // Join Test
  std::string p6 = fdp.ConsumeRandomLengthString();
  std::string p7 = fdp.ConsumeRandomLengthString();
  char* join_buff = (char*) malloc(p6.length() + p7.length() + 1);
  cwk_path_join(p6.c_str(), p7.c_str(), join_buff, p6.length() + p7.length() + 1);

  // Normalize Test
  std::string p8 = fdp.ConsumeRandomLengthString();
  char* norm_buff = (char*) malloc(p8.length() + 1);
  cwk_path_normalize(p8.c_str(), norm_buff, p8.length() + 1);

  // Intersection Test
    std::string p9 = fdp.ConsumeRandomLengthString();
    std::string p10 = fdp.ConsumeRandomLengthString();
    cwk_path_get_intersection(p9.c_str(), p10.c_str());

    // Segment Iteration
    std::string p11 = fdp.ConsumeRandomLengthString();
    struct cwk_segment segment;
    cwk_path_get_first_segment(p11.c_str(), &segment);
    do {
        noop;
    } while (cwk_path_get_next_segment(&segment));
  delete join_buff;
  delete norm_buff;

  return 0;
}
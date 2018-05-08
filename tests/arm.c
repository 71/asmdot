#include "greatest.h"
#include "../include/arm.h"

TEST arm_header_should_be_readable() {
  PASS();
}

TEST should_emit_correct_buffers() {
  int* buf = malloc(10);
  int* origin = buf;

  ASSERT_EQ(4, b(EQ, &buf));
  ASSERT_EQ(origin + 1, buf);
  ASSERT_EQ_FMT(0xFCFFFFEA, buf[-1], "%d");

  free(buf);

  PASS();
}

SUITE(arm_suite) {
  RUN_TEST(arm_header_should_be_readable);
  RUN_TEST(should_emit_correct_buffers);
}


#ifndef TEST_ALL
GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
  GREATEST_MAIN_BEGIN();
  RUN_SUITE(arm_suite);
  GREATEST_MAIN_END();
}
#endif

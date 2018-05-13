#include "greatest.h"
#include "../include/x86.c"

TEST x86_header_should_be_readable() {
  PASS();
}

TEST should_emit_correct_opcode() {
  byte* buf = malloc(10);
  byte* origin = buf;

  ASSERT_EQ(1, ret(&buf));
  ASSERT_EQ(origin + 1, buf);
  ASSERT_EQ_FMT(0xC3, buf[-1], "%d");

  free(buf);

  PASS();
}

SUITE(x86_suite) {
  RUN_TEST(x86_header_should_be_readable);
  RUN_TEST(should_emit_correct_opcode);
}


#ifndef TEST_ALL
GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
  GREATEST_MAIN_BEGIN();
  RUN_SUITE(x86_suite);
  GREATEST_MAIN_END();
}
#endif

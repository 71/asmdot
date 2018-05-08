#define TEST_ALL

#include "arm.c"
#include "x86.c"

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
  GREATEST_MAIN_BEGIN();

  RUN_SUITE(arm_suite);
  RUN_SUITE(x86_suite);

  GREATEST_MAIN_END();
}

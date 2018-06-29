#include "greatest.h"
#include "../src/arm.c"

TEST should_encode_single_cps_instruction() {
    void* buf = malloc(4);
    void* origin = buf;

    arm_cps(&buf, USRMode);

    ASSERT_EQ((char*)buf, (char*)origin + 4);
    ASSERT_MEM_EQ(origin, "\x10\x00\x02\xf1", 4);

    free(origin);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();

    RUN_TEST(should_encode_single_cps_instruction);

    GREATEST_MAIN_END();
}

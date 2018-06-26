#include "greatest.h"
#include "../x86.c"

TEST should_assemble_single_ret_instruction() {
    void* buf = malloc(1);
    void* origin = buf;

    x86_ret(&buf);

    ASSERT_EQ((char*)buf, (char*)origin + 1);
    ASSERT_MEM_EQ(origin, "\xc3", 1);

    free(origin);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();

    RUN_TEST(should_assemble_single_ret_instruction);

    GREATEST_MAIN_END();
}

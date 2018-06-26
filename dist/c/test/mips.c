#include "greatest.h"
#include "../mips.c"

TEST should_assemble_single_addi_instruction() {
    void* buf = malloc(4);
    void* origin = buf;

    addi(&buf, Reg_T1, Reg_T2, 0);

    ASSERT_EQ((char*)buf, (char*)origin + 4);
    ASSERT_MEM_EQ(origin, "\x00\x00\x49\x21", 4);

    free(origin);
    PASS();
}

GREATEST_MAIN_DEFS();

int main(int argc, char** argv) {
    GREATEST_MAIN_BEGIN();

    RUN_TEST(should_assemble_single_addi_instruction);

    GREATEST_MAIN_END();
}

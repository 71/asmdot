#ifndef ASM_ALL_TESTS
  #define CATCH_CONFIG_MAIN
#endif

#include <sstream>
#include "catch"
#include "../src/mips"

using Catch::Matchers::Equals;

TEST_CASE("mips tests", "[mips]") {
    std::ostringstream buf;

    SECTION("should assemble single addi instruction") {
        addi(buf, Reg_T1, Reg_T2, 0);

        REQUIRE( buf.tellp() == 4);
        REQUIRE_THAT(buf.str(), Equals("\x00\x00\x49\x21"));
    }
}

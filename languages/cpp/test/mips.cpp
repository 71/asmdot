#ifndef ASM_ALL_TESTS
  #define CATCH_CONFIG_MAIN
#endif

#include <sstream>
#include "catch.hpp"
#include "../src/mips.cpp"

using Catch::Matchers::Equals;

using namespace std::string_literals;

TEST_CASE("mips tests", "[mips]") {
    std::ostringstream buf;

    SECTION("should assemble single addi instruction") {
        mips::addi(buf, mips::Reg::T1, mips::Reg::T2, 0);

        REQUIRE( buf.tellp() == 4 );
        REQUIRE_THAT(buf.str(), Equals("\x00\x00\x49\x21"s));
    }
}

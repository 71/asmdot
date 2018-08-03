#ifndef ASM_ALL_TESTS
  #define CATCH_CONFIG_MAIN
#endif

#include <sstream>
#include "catch.hpp"
#include "../src/x86.cpp"

using Catch::Matchers::Equals;

using namespace std::string_literals;

TEST_CASE("x86 tests", "[x86]") {
    std::ostringstream buf;

    SECTION("should assemble single ret instruction") {
        x86::ret(buf);

        REQUIRE( buf.tellp() == 1 );
        REQUIRE_THAT(buf.str(), Equals("\xc3"s));
    }
}

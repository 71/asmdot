#ifndef ASM_ALL_TESTS
  #define CATCH_CONFIG_MAIN
#endif

#include <sstream>
#include "catch"
#include "../src/x86"

using Catch::Matchers::Equals;

TEST_CASE("x86 tests", "[x86]") {
    std::ostringstream buf;

    SECTION("should assemble single ret instruction") {
        ret(buf);

        REQUIRE( buf.tellp() == 1);
        REQUIRE_THAT(buf.str(), Equals("\xc3"));
    }
}

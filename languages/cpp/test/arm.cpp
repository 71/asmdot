#ifndef ASM_ALL_TESTS
  #define CATCH_CONFIG_MAIN
#endif

#include <sstream>
#include "catch"
#include "../src/arm"

using Catch::Matchers::Equals;

TEST_CASE("arm tests", "[arm]") {
    std::ostringstream buf;

    SECTION("should encode single cps instruction") {
        cps(buf, USRMode);

        REQUIRE( buf.tellp() == 4);
        REQUIRE_THAT(buf.str(), Equals("\x10\x00\x02\xf1"));
    }
}

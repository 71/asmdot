#ifndef ASM_ALL_TESTS
  #define CATCH_CONFIG_MAIN
#endif

#include <sstream>
#include "catch.hpp"
#include "../src/arm.cpp"

using Catch::Matchers::Equals;

using namespace std::string_literals;

TEST_CASE("arm tests", "[arm]") {
    std::ostringstream buf;

    SECTION("should encode single cps instruction") {
        arm::cps(buf, arm::Mode::USR);

        REQUIRE( buf.tellp() == 4 );
        REQUIRE_THAT(buf.str(), Equals("\x10\x00\x02\xf1"s));
    }
}

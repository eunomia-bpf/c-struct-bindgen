#include <inttypes.h>
#include <cassert>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <random>
#include <string>
#include <thread>
#include "../../test/asserts/struct-nesting.h"
#include "../../test/asserts/struct-nesting.bpf.o.json-binding.h"

TEST_CASE("test serilization & deserilization for nesting-structs",
          "[event1]") {
    struct S3 st3 = {.a = 123, .b = 234};
    struct S4 st = {.st = st3};
    char* json_str = marshal_struct_S4__to_json_str(&st);
    struct S4 dst;
    unmarshal_struct_S4__from_json_str(&dst, json_str);
    REQUIRE((dst.st.a == st3.a && dst.st.b == st3.b));
    cJSON_free(json_str);
}
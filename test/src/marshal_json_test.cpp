/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunommia-bpf
 * All rights reserved.
 */

#include <cassert>
#include <cstring>
#include <fstream>
#include <iostream>
#include <thread>
#include <string>
#include <thread>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include "../../test/asserts/event.h"
#include "../../test/asserts/source.bpf.o.json-binding.h"

using namespace std;

TEST_CASE("test marshal and unmarshal event", "[event1]")
{
    struct event src1 = { 0 };
    // generate random data for struct src1
    for (int i = 0; i < sizeof(src1); i++) {
        ((char *)&src1)[i] = rand() % 256;
    }
    // char *buffer = marshal_struct_event__to_json_str(&src1);
    // REQUIRE(buffer);
    // printf("%s\n", buffer);
    // struct event dst1 = { 0 };
    // auto dst = unmarshal_struct_event__from_json_str(&dst1, buffer);
    // REQUIRE(dst);
    // REQUIRE(memcmp(&src1, &dst1, sizeof(struct event)) == 0);
    // TODO: fix this and more test
}

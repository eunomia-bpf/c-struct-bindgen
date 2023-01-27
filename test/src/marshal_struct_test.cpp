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
#include "../../test/asserts/source.bpf.o.binding.h"

TEST_CASE("test marshal and unmarshal event", "[event1]")
{
    struct event src1 = { 0 };
    // generate random data for struct src1
    for (int i = 0; i < sizeof(src1); i++) {
        ((char *)&src1)[i] = rand() % 256;
    }
    char buffer[1024];
    marshal_struct_event__to_binary(buffer, &src1);
    struct event dst1 = { 0 };
    unmarshal_struct_event__from_binary(&dst1, buffer);
    REQUIRE(memcmp(&src1, &dst1, sizeof(struct event)) == 0);
}

void
compare_event2(event2 &src2, event2 &dst2)
{
    REQUIRE(src2.a == dst2.a);
    REQUIRE(src2.x == dst2.x);
    REQUIRE(src2.y == dst2.y);
    REQUIRE(src2.z == dst2.z);
    REQUIRE(memcmp(src2.comm, dst2.comm, sizeof(src2.comm)) == 0);
}

TEST_CASE("test marshal and unmarshal event", "[event2]")
{
    struct event2 src2 = { 0 };
    // generate random data for struct src2
    for (int i = 0; i < sizeof(src2); i++) {
        ((char *)&src2)[i] = rand() % 256;
    }
    char buffer[1024];
    marshal_struct_event2__to_binary(buffer, &src2);
    struct event2 dst2 = { 0 };
    unmarshal_struct_event2__from_binary(&dst2, buffer);
    compare_event2(src2, dst2);
}

TEST_CASE("test nested struct", "[event3]")
{
    struct event3 src3 = { 0 };
    // generate random data for struct src3
    for (int i = 0; i < sizeof(src3); i++) {
        ((char *)&src3)[i] = rand() % 256;
    }
    char buffer[1024];
    marshal_struct_event3__to_binary(buffer, &src3);
    struct event3 dst3 = { 0 };
    unmarshal_struct_event3__from_binary(&dst3, buffer);
    REQUIRE(src3.g == dst3.g);
    compare_event2(src3.e2, dst3.e2);
}

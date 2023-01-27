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
#include "struct-bindgen/bpf_object_reader.h"

using namespace eunomia;

TEST_CASE("test load and parse bpf object file", "[source]")
{
    bpf_object_reader reader("../../test/asserts/source.bpf.o");
    auto btf_data = reader.get_btf_data();
    REQUIRE(btf_data != nullptr);
}

TEST_CASE("test load and parse bpf object from memory", "[source]")
{
        std::ifstream file("../../test/asserts/source.bpf.o", std::ios::binary);
        std::vector<char> buffer(std::istreambuf_iterator<char>(file), {});
        bpf_object_reader reader(buffer);
        auto btf_data = reader.get_btf_data();
        REQUIRE(btf_data != nullptr);
}

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
#include "struct-bindgen/gen-c-struct-binding.h"
#include "struct-bindgen/bpf_object_reader.h"

using namespace eunomia;
using namespace std;

TEST_CASE("test generate c struct", "[event1]")
{
    bpf_object_reader reader("../../test/asserts/source.bpf.o");
    auto btf_data = reader.get_btf_data();

    c_struct_binding_generator generator(btf_data, "sigsnoop");
    string output;
    generator.generate_for_all_structs(output);
    std::cout << output << std::endl;
}

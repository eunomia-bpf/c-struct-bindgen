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
#include <cstdio>
#include "../../test/asserts/event.h"
#include "../../test/asserts/source.bpf.o.json-binding.h"
#include <random>
#include <inttypes.h>
using namespace std;
#define lengthof(arr) (sizeof(arr) / sizeof(arr[0]))
TEST_CASE("test marshal and unmarshal event", "[event1]") {
    std::mt19937 gen;
    gen.seed(time(nullptr));
    std::uniform_int_distribution<unsigned long long> rand(0, UINT64_MAX);
    struct event src1 = {0};
    // Ensure that padding bytes are empty
    src1.pid = rand(gen);
    src1.tpid = rand(gen);
    src1.sig = rand(gen);
    src1.ret = rand(gen);

    for (int i = 0; i < lengthof(src1.comm); i++)
        src1.comm[i] = rand(gen);
    char* buffer = marshal_struct_event__to_json_str(&src1);
    REQUIRE(buffer);
    cout << buffer << endl;
    struct event dst1 = {0};
    auto dst = unmarshal_struct_event__from_json_str(&dst1, buffer);
    cJSON_free(buffer);
    REQUIRE(dst);
    // printf("pid: %d, tpid: %d, sig: %d, ret:%d \n", (int)(dst->pid),
    //        (int)(dst->tpid), (int)(dst->sig), (int)(dst->ret));
    cout << "Deserialized: pid: " << dst->pid << " tpid: " << dst->tpid
         << " sig: " << dst->sig << " ret: " << dst->ret << endl;
    cout << "Array elements: " << endl;
    for (int i = 0; i < sizeof(dst1.comm) / sizeof(dst1.comm[0]); i++) {
        cout << (int)(dst1.comm[i]) << " ";
        if ((i + 1) % 5 == 0)
            cout << endl;
    }
    cout << endl;
    REQUIRE(memcmp(&src1, &dst1, sizeof(struct event)) == 0);
}

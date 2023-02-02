//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!

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

TEST_CASE("test serilization & deserilization strings (1-dim char array)",
          "[event1]") {
    struct event st;
    struct event dst;
    memset(&st, 0, sizeof(st));
    memset(&dst, 0, sizeof(dst));

    strcpy(st.comm, "abcdeABCDE12");
    char* json_str = marshal_struct_event__to_json_str(&st);

    cJSON* json = cJSON_Parse(json_str);
    cJSON* comm_obj = cJSON_GetObjectItem(json, "comm");
    REQUIRE(cJSON_IsString(comm_obj));
    REQUIRE(strcmp(comm_obj->valuestring, st.comm) == 0);
    cJSON_Delete(json);
    unmarshal_struct_event__from_json_str(&dst, json_str);
    REQUIRE(memcmp(&st, &dst, sizeof(st)) == 0);
    cJSON_free(json_str);
}
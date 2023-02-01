/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunommia-bpf
 * All rights reserved.
 */

#include <cassert>
#include <catch2/catch_test_macros.hpp>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iostream>
#include <string>
#include <thread>
#include "../../test/asserts/cJSON.h"
#include "../../test/asserts/simple-2dim-array.h"
#include "../../test/asserts/simple-2dim-array.bpf.o.json-binding.h"

using namespace std;

static void print_S1(std::ostream& os, const S1& st) {
    os << "a=" << st.a << endl;
    os << "b=" << st.b << endl;
    os << "array=" << endl;
    for (const auto& x : st.c) {
        for (const auto& y : x) {
            os << (int)y << "\t";
        }
        os << endl;
    }
}

TEST_CASE("test json serilization for struct with array", "[event1]") {
    struct S1 st;
    FILE* fp = fopen("/dev/urandom", "r");
    REQUIRE(fp != nullptr);
    size_t nread = fread(&st, 1, sizeof(st), fp);
    REQUIRE(nread == sizeof(st));
    fclose(fp);
    cout << "struct representation:" << endl;
    print_S1(cout, st);
    char* json_str = marshal_struct_S1__to_json_str(&st);
    REQUIRE(json_str);
    cout << "JSON str: " << json_str << endl;
    cJSON* json = cJSON_Parse(json_str);
    REQUIRE(json);
    REQUIRE(cJSON_GetNumberValue(cJSON_GetObjectItem(json, "a")) == st.a);
    REQUIRE(cJSON_GetNumberValue(cJSON_GetObjectItem(json, "b")) == st.b);
    cJSON* arr_c = cJSON_GetObjectItem(json, "c");
    REQUIRE(arr_c != nullptr);
    REQUIRE(cJSON_IsArray(arr_c));
    cJSON *elem1, *elem2;
    int i = 0;
    cJSON_ArrayForEach(elem1, arr_c) {
        REQUIRE(cJSON_IsArray(elem1));
        int j = 0;
        cJSON_ArrayForEach(elem2, elem1) {
            REQUIRE(cJSON_IsNumber(elem2));
            int numval = (int)cJSON_GetNumberValue(elem2);
            REQUIRE((int)st.c[i][j] == numval);
            j++;
        };
        i++;
    };
    cJSON_Delete(json);
    cJSON_free(json_str);
}

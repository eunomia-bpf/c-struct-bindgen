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
#include "../../test/asserts/pointer-and-int64.h"
#include "../../test/asserts/pointer-and-int64.bpf.o.json-binding.h"

using namespace std;
static bool str_ull_cmp(const char* str, unsigned long long val) {
    char buf[30];
    snprintf(buf, sizeof(buf), "%llu", val);
    return strcmp(buf, str) == 0;
}
TEST_CASE("test serilization & deserilization for pointer and 64bit integer",
          "[event1]") {
    struct S2 st;
    struct S2 dst;
    memset(&st, 0, sizeof(st));
    memset(&dst, 0, sizeof(dst));
    {
        FILE* fp = fopen("/dev/urandom", "r");
        REQUIRE(fp != nullptr);
        // size_t nread = fread(&st, 1, sizeof(st), fp);
        // REQUIRE(nread == sizeof(st));
        fread(&st.i64, 1, sizeof(st.i64), fp);
        fread(&st.ptr, 1, sizeof(st.ptr), fp);
        fread(&st.arr, 1, sizeof(st.arr), fp);
        fclose(fp);
    }
    cout << "i64 = " << st.i64 << endl;
    cout << "ptr = " << (unsigned long long)st.ptr << endl;
    for (int i = 0; i < 3; i++)
        cout << "arr " << i << " = " << st.arr[i] << endl;
    char* serialized_str = marshal_struct_S2__to_json_str(&st);

    cout << "Serialized: " << serialized_str << endl;
    unmarshal_struct_S2__from_json_str(&dst, serialized_str);

    REQUIRE(memcmp(&st, &dst, sizeof(st)) == 0);
    cJSON* json = cJSON_Parse(serialized_str);
    cJSON_free(serialized_str);

    REQUIRE(json != nullptr);
    {
        cJSON* i64obj = cJSON_GetObjectItemCaseSensitive(json, "i64");
        REQUIRE(i64obj != nullptr);
        REQUIRE(str_ull_cmp(i64obj->valuestring, (unsigned long long)st.i64));
    }

    {
        cJSON* ptrobj = cJSON_GetObjectItemCaseSensitive(json, "ptr");
        REQUIRE(ptrobj != nullptr);
        REQUIRE(str_ull_cmp(ptrobj->valuestring, (unsigned long long)st.ptr));
    }
    {
        cJSON* arrobj = cJSON_GetObjectItemCaseSensitive(json, "arr");
        REQUIRE(arrobj != nullptr);
        cJSON* elem;
        REQUIRE(cJSON_IsArray(arrobj));
        int i = 0;
        cJSON_ArrayForEach(elem, arrobj) {
            REQUIRE(cJSON_IsString(elem));
            REQUIRE(
                str_ull_cmp(elem->valuestring, (unsigned long long)st.arr[i]));
            i++;
        };
    }
    cJSON_Delete(json);
    ;
}

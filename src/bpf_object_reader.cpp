/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2023, eunommia-bpf
 * All rights reserved.
 */
#include <iostream>
#include <thread>
#include <string>
#include <sstream>
#include "struct-bindgen/bpf_object_reader.h"
#include "json.hpp"

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
}

using json = nlohmann::json;
namespace eunomia {
thread_local bool verbose_local = false;
static int
libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
    if (level == LIBBPF_DEBUG && !verbose_local)
        return 0;
    return vfprintf(stderr, format, args);
}

int
bpf_object_reader::init_libbpf(void)
{
    libbpf_set_print(libbpf_print_fn);
}

bpf_object_reader::bpf_object_reader(std::vector<char> bpf_object_buffer)
{
    init_libbpf();
    auto additional_btf_file = getenv("BTF_FILE_PATH");
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, openopts);
    if (additional_btf_file != NULL) {
        openopts.btf_custom_path = strdup(additional_btf_file);
    }
    bpf_object *new_obj = bpf_object__open_mem(
        bpf_object_buffer.data(), bpf_object_buffer.size(), &openopts);
    if (!new_obj) {
        std::cerr << "failed to open bpf object file: " << std::endl;
        return;
    }
    obj.reset(new_obj);
}

bpf_object_reader::bpf_object_reader(const char *path)
{
    init_libbpf();
    auto additional_btf_file = getenv("BTF_FILE_PATH");
    DECLARE_LIBBPF_OPTS(bpf_object_open_opts, openopts);
    if (additional_btf_file != NULL) {
        openopts.btf_custom_path = strdup(additional_btf_file);
    }
    bpf_object *new_obj = bpf_object__open_file(path, &openopts);
    if (!new_obj) {
        std::cerr << "failed to open bpf object file: " << path << std::endl;
        return;
    }
    obj.reset(new_obj);
}

btf *
bpf_object_reader::get_btf_data(void)
{
    assert(obj);
    return bpf_object__btf(obj.get());
}
}
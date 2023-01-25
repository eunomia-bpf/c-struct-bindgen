/* SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
 *
 * Copyright (c) 2022, Yusheng Zheng
 * All rights reserved.
 */
#ifndef EUNOMIA_BPF_OBJECT_READER_HPP_
#define EUNOMIA_BPF_OBJECT_READER_HPP_

#include <memory>
#include <iostream>
#include <mutex>
#include <string>
#include <vector>

extern "C" {
struct bpf_object;
void bpf_object__close(bpf_object *object);
struct btf;
}

namespace eunomia {

class bpf_object_reader
{
    std::unique_ptr<bpf_object, decltype(&bpf_object__close)> obj {
        nullptr, bpf_object__close
    };
    int init_libbpf(void);

  public:
    bpf_object_reader(std::vector<char> bpf_object_buffer);
    bpf_object_reader(const char *path);
    /// @brief get raw btf data from object
    btf *get_btf_data(void);
};
} // namespace eunomia

#endif

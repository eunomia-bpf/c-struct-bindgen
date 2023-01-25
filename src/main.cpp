#include <fstream>
#include <iostream>
#include <vector>
#include "struct-bindgen/bpf_object_reader.h"

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/utsname.h>
}

using namespace eunomia;

/// a simple loader for eunomia bpf program
int
main(int argc, char *argv[])
{
    if (argc != 2) {
        std::cerr << "Usage: " << argv[0]
                  << " <bpf_object_file>" << std::endl;
        return -1;
    }
    bpf_object_reader reader(argv[1]);
    auto btf_data = reader.get_btf_data();

    return 0;
}
#include <fstream>
#include <iostream>
#include <vector>
#include "struct-bindgen/bpf_object_reader.h"
#include "struct-bindgen/gen-c-struct-binding.h"
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
using namespace std;
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
    if (btf_data == nullptr) {
        std::cerr << "failed to get btf data" << std::endl;
        return -1;
    }
    c_struct_binding_generator generator(btf_data);
    string output;
    generator.generate_for_all_structs(output);
    return 0;
}
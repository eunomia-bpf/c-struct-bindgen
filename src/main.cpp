#include <fstream>
#include <iostream>
#include <vector>
#include "struct-bindgen/bpf_object_reader.h"
#include "struct-bindgen/gen-c-struct-binding.h"
#include "argparse.hpp"

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
    argparse::ArgumentParser program("struct-bindgen");

    program.add_argument("object").help("path to bpf object file");

    program.add_argument("-j", "--json")
        .help("output json binding")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-c", "--marshal")
        .help("output basic marshal binding")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-p", "--pragma-once")
        .help("output bdebug info")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-d", "--debug")
        .help("output bdebug info")
        .default_value(false)
        .implicit_value(true);

    program.add_argument("-s", "--struct")
        .help("output struct layout")
        .default_value(true)
        .implicit_value(false);

    try {
        program.parse_args(argc, argv);
    } catch (const std::runtime_error &err) {
        std::cerr << err.what() << std::endl;
        std::cerr << program;
        std::exit(1);
    }
    std::string object_path = program.get<std::string>("object");
    bpf_object_reader reader(object_path.c_str());
    auto btf_data = reader.get_btf_data();
    if (btf_data == nullptr) {
        std::cerr << "failed to get btf data" << std::endl;
        return -1;
    }
    auto c = config{ program.get<bool>("--pragma-once"), argv[1] };

    if (program["--json"] == true) {
        c_struct_json_generator generator(btf_data, c);
        string output;
        generator.generate_for_all_structs(output);
        std::cout << output << std::endl;
    }
    else if (program["--marshal"] == true) {
        c_struct_marshal_generator generator(btf_data, c);
        string output;
        generator.generate_for_all_structs(output);
        std::cout << output << std::endl;
    }
    else if (program["--debug"] == true) {
        debug_binding_generator generator(btf_data, c);
        string output;
        generator.generate_for_all_structs(output);
        std::cout << output << std::endl;
    }
    else if (program["--struct"] == true) {
        c_struct_define_generator generator(btf_data, c);
        string output;
        generator.generate_for_all_structs(output);
        std::cout << output << std::endl;
    }
    return 0;
}
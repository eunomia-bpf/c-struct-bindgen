
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <cstring>
#include "struct-bindgen/gen-c-struct-binding.h"

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
}

using namespace eunomia;
#define BUFFER_SIZE 1024

void
c_struct_json_generator::start_generate(std::string &output)
{
    auto header = get_c_file_header();
    header += R"(
#include <assert.h>
#include <string.h>
#include <stdint.h>
)";
    output += header;
}

void
c_struct_json_generator::end_generate(std::string &output)
{
    output += get_c_file_footer();
}

void
c_struct_json_generator::enter_struct_def(std::string &output, struct_info info)
{
    if (walk_count == 0) {
        // generate marshal function
        const char *function_proto = R"(
static void marshal_struct_%s__to_binary(void *_dst, const struct %s *src) {
    // avoid -Wpointer-arith warning
    char* dst = (char*)_dst;
    assert(dst && src);
)";
        char struct_def[BUFFER_SIZE];
        snprintf(struct_def, sizeof(struct_def), function_proto,
                 info.struct_name, info.struct_name);
        output += struct_def;
    }
    else {
        // generate unmarshal function
        const char *function_proto = R"(
static void unmarshal_struct_%s__from_binary(struct %s *dst, const void *_src) {
    // avoid -Wpointer-arith warning
    const char* src = (const char*)_src;
    assert(dst && src);
)";
        char struct_def[BUFFER_SIZE];
        snprintf(struct_def, sizeof(struct_def), function_proto,
                 info.struct_name, info.struct_name);
        output += struct_def;
    }
}

void
c_struct_json_generator::exit_struct_def(std::string &output, struct_info info)
{
    output += "}\n";
}

void
c_struct_json_generator::marshal_field(std::string &output, field_info info)
{
    uint32_t offset = info.bit_off / 8;

    if (strcmp(info.field_type, "array") == 0) {
        const char *array_type_format = R"(    memcpy(dst + %d, src->%s, %d);
)";
        char field_marshal_code[BUFFER_SIZE];
        snprintf(field_marshal_code, sizeof(field_marshal_code),
                 array_type_format, offset, info.field_name, info.size);
        output += field_marshal_code;
    }
    else if (strcmp(info.field_type, "struct") == 0) {
        const char *struct_type_format =
            R"(    marshal_struct_%s__to_binary(dst + %d, &src->%s);
)";
        char field_marshal_code[BUFFER_SIZE];
        snprintf(field_marshal_code, sizeof(field_marshal_code),
                 struct_type_format, info.field_type_name, offset,
                 info.field_name);
        output += field_marshal_code;
    }
    else if (strcmp(info.field_type, "union") == 0) {
        const char *union_type_format =
            R"(    marshal_union_%s__to_binary(dst + %d, &src->%s);
)";
        char field_marshal_code[BUFFER_SIZE];
        snprintf(field_marshal_code, sizeof(field_marshal_code),
                 union_type_format, info.field_type_name, offset,
                 info.field_name);
        output += field_marshal_code;
    }
    else {
        const char *basic_type_format = R"(    *(%s*)(dst + %d) = src->%s;
)";
        char field_marshal_code[BUFFER_SIZE];
        snprintf(field_marshal_code, sizeof(field_marshal_code),
                 basic_type_format, info.field_type, offset, info.field_name);
        output += field_marshal_code;
    }
}

void
c_struct_json_generator::unmarshal_field(std::string &output, field_info info)
{
    uint32_t offset = info.bit_off / 8;

    if (strcmp(info.field_type, "array") == 0) {
        const char *array_type_format = R"(    memcpy(dst->%s, src + %d, %d);
)";
        char field_marshal_code[BUFFER_SIZE];
        snprintf(field_marshal_code, sizeof(field_marshal_code),
                 array_type_format, info.field_name, offset, info.size);
        output += field_marshal_code;
    }
    else if (strcmp(info.field_type, "struct") == 0) {
        const char *struct_type_format =
            R"(    unmarshal_struct_%s__from_binary(&dst->%s, src + %d);
)";
        char field_marshal_code[BUFFER_SIZE];
        snprintf(field_marshal_code, sizeof(field_marshal_code),
                 struct_type_format, info.field_type_name, info.field_name,
                 offset);
        output += field_marshal_code;
    }
    else if (strcmp(info.field_type, "union") == 0) {
        const char *union_type_format =
            R"(    unmarshal_union_%s__from_binary(&dst->%s, src + %d);
)";
        char field_marshal_code[BUFFER_SIZE];
        snprintf(field_marshal_code, sizeof(field_marshal_code),
                 union_type_format, info.field_type_name, info.field_name,
                 offset);
        output += field_marshal_code;
    }
    else {
        const char *basic_type_format = R"(    dst->%s = *(%s*)(src + %d);
)";
        char field_marshal_code[BUFFER_SIZE];
        snprintf(field_marshal_code, sizeof(field_marshal_code),
                 basic_type_format, info.field_name, info.field_type, offset);
        output += field_marshal_code;
    }
}

void
c_struct_json_generator::enter_struct_field(std::string &output,
                                            field_info info)
{
    if (info.bit_sz != 0) {
        std::cerr << "bitfield not supported" << std::endl;
        throw std::runtime_error("bitfield not supported");
    }
    if (walk_count == 0) {
        marshal_field(output, info);
    }
    else {
        unmarshal_field(output, info);
    }
}

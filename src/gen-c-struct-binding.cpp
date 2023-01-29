
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
#include <sys/utsname.h>
}

using namespace eunomia;

#define BUFFER_SIZE 1024

static void
btf_dump_event_printf(void *ctx, const char *fmt, va_list args)
{
    auto printer = static_cast<binding_generator_base::sprintf_printer *>(ctx);
    printer->vsprintf_event(fmt, args);
}

int
binding_generator_base::sprintf_printer::vsprintf_event(const char *fmt,
                                                        va_list args)
{
    char output_buffer_pointer[EVENT_SIZE];
    int res = vsnprintf(output_buffer_pointer, EVENT_SIZE, fmt, args);
    if (res < 0) {
        return res;
    }
    buffer.append(output_buffer_pointer);
    return res;
}

int
binding_generator_base::sprintf_printer::snprintf_event(size_t __maxlen,
                                                        const char *fmt, ...)
{
    char output_buffer_pointer[EVENT_SIZE];
    if (__maxlen > EVENT_SIZE) {
        __maxlen = EVENT_SIZE;
    }
    va_list args;
    va_start(args, fmt);
    int res = vsnprintf(output_buffer_pointer, __maxlen, fmt, args);
    va_end(args);
    if (res < 0) {
        return res;
    }
    buffer.append(output_buffer_pointer);
    return res;
}

int
binding_generator_base::sprintf_printer::sprintf_event(const char *fmt, ...)
{
    va_list args;
    va_start(args, fmt);
    int res = vsprintf_event(fmt, args);
    va_end(args);
    return res;
}

static int
get_btf_type_str(unsigned int id, const struct btf *btf, std::string &out_type)
{
    DECLARE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts, opts, .field_name = "",
                        .indent_level = 2, );
    binding_generator_base::sprintf_printer printer;
    struct btf_dump *d =
        btf_dump__new(btf, btf_dump_event_printf, &printer, nullptr);
    if (!d) {
        return -1;
    }
    std::unique_ptr<btf_dump, void (*)(btf_dump *)> btf_dumper_keeper{
        d, btf_dump__free
    };
    printer.reset();
    int err = btf_dump__emit_type_decl(d, id, &opts);
    if (err < 0) {
        return err;
    }
    out_type = printer.buffer;
    return 0;
}

void
binding_generator_base::walk_all_structs(std::string &output)
{
    const struct btf_type *t;
    int cnt = btf__type_cnt(btf_data);
    int start_id = 1;
    for (int i = start_id; i < cnt; i++) {
        t = btf__type_by_id(btf_data, i);
        if (!btf_is_struct(t))
            continue;
        walk_struct_for_id(output, i);
    }
}

void
binding_generator_base::generate_for_all_structs(std::string &output)
{
    start_generate(output);
    for (walk_count = 0; walk_count < max_walk_count; walk_count++) {
        walk_all_structs(output);
    }
    end_generate(output);
}

void
binding_generator_base::walk_struct_for_id(std::string &output, int type_id)
{
    auto t = btf__type_by_id(btf_data, type_id);
    if (!t) {
        std::cerr << "type id " << type_id << " not found" << std::endl;
        throw std::runtime_error("type id not found");
    }
    auto struct_name = btf__name_by_offset(btf_data, t->name_off);
    if (!btf_is_struct(t)) {
        std::cerr << "type id " << type_id << " is not a struct" << std::endl;
        throw std::runtime_error("type id is not a struct");
    }
    btf_member *m = btf_members(t);
    __u16 vlen = BTF_INFO_VLEN(t->info);
    enter_struct_def(output, struct_name, vlen);
    for (size_t i = 0; i < vlen; i++, m++) {
        // found btf type id
        const char *member_name = btf__name_by_offset(btf_data, m->name_off);
        auto member_type_id = m->type;
        uint32_t bit_off, bit_sz;
        std::string type_str, field_type_name;

        if (BTF_INFO_KFLAG(t->info)) {
            bit_off = BTF_MEMBER_BIT_OFFSET(m->offset);
            bit_sz = BTF_MEMBER_BITFIELD_SIZE(m->offset);
        }
        else {
            bit_off = m->offset;
            bit_sz = 0;
        }
        uint32_t size = btf__resolve_size(btf_data, m->type);
        auto field_type = btf__type_by_id(btf_data, m->type);
        if (btf_is_struct(field_type)) {
            type_str = "struct";
            field_type_name =
                btf__name_by_offset(btf_data, field_type->name_off);
        }
        else if (btf_is_union(field_type)) {
            type_str = "union";
            field_type_name =
                btf__name_by_offset(btf_data, field_type->name_off);
        }
        else if (btf_is_enum(field_type)) {
            type_str = "enum";
            field_type_name =
                btf__name_by_offset(btf_data, field_type->name_off);
        }
        else if (btf_is_array(field_type)) {
            type_str = "array";
            if (btf_is_composite(field_type)) {
                std::cerr << "composite array not supported" << std::endl;
                throw std::runtime_error("composite array not supported");
            }
            else {
                int err =
                    get_btf_type_str(member_type_id, btf_data, field_type_name);
                if (err < 0) {
                    std::cerr << "failed to get type string for " << member_name
                              << " member_type_id" << member_type_id
                              << std::endl;
                    throw std::runtime_error("failed to get type string");
                }
            }
        }
        else {
            int err = get_btf_type_str(member_type_id, btf_data, type_str);
            if (err < 0) {
                std::cerr << "failed to get type string for " << member_name
                          << " member_type_id" << member_type_id << std::endl;
                throw std::runtime_error("failed to get type string");
            }
        }
        enter_struct_field(output,
                           field_info{ m->type, member_name, type_str.c_str(),
                                       field_type_name.c_str(), bit_off, size,
                                       bit_sz });
    }
    exit_struct_def(output, struct_name);
}

std::string
binding_generator_base::get_c_file_header()
{
    char header_buffer[BUFFER_SIZE];
    std::string header;
    std::string program_once_header;
    std::string header_name =
        basename(generator_config.source_file_path.c_str());
    if (generator_config.use_pragma_once) {
        program_once_header = "\n#pragma once\n";
    }
    else {
        std::string upper_name;
        std::transform(header_name.begin(), header_name.end(),
                       std::back_inserter(upper_name), ::toupper);
        // replace . with _
        std::replace(upper_name.begin(), upper_name.end(), '.', '_');
        const char *program_once_format = R"(
#ifndef __STRUCT_MARSHAL_%s_H__
#define __STRUCT_MARSHAL_%s_H__
    )";
        snprintf(header_buffer, sizeof(header_buffer), program_once_format,
                 upper_name.c_str(), upper_name.c_str());
        program_once_header = header_buffer;
    }

    const char *header_format = R"(
// Code generated by c-struct-bindgen and ecc - DO NOT EDIT
// See https://github.com/eunomia-bpf/c-struct-bindgen for details.
// struct-bindgen versions: %s
// source file path: %s)";
    snprintf(header_buffer, sizeof(header_buffer), header_format,
             EUNOMIA_VERSION, generator_config.source_file_path.c_str());
    header = header_buffer;
    header += program_once_header;
    return header;
}

std::string
binding_generator_base::get_c_file_footer()
{
    if (!generator_config.use_pragma_once) {
        return "\n#endif\n";
    }
    return "";
}

void
c_struct_marshal_generator::start_generate(std::string &output)
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
c_struct_marshal_generator::end_generate(std::string &output)
{
    output += get_c_file_footer();
}

void
c_struct_marshal_generator::enter_struct_def(std::string &output,
                                             const char *struct_name,
                                             uint16_t vlen)
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
        snprintf(struct_def, sizeof(struct_def), function_proto, struct_name,
                 struct_name);
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
        snprintf(struct_def, sizeof(struct_def), function_proto, struct_name,
                 struct_name);
        output += struct_def;
    }
}

void
c_struct_marshal_generator::exit_struct_def(std::string &output,
                                            const char *struct_name)
{
    output += "}\n";
}

void
c_struct_marshal_generator::marshal_field(std::string &output, field_info info)
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
c_struct_marshal_generator::unmarshal_field(std::string &output,
                                            field_info info)
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
c_struct_marshal_generator::enter_struct_field(std::string &output,
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

void
c_struct_define_generator::start_generate(std::string &output)
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
c_struct_define_generator::end_generate(std::string &output)
{
    output += get_c_file_footer();
}

void
c_struct_define_generator::enter_struct_def(std::string &output,
                                            const char *struct_name,
                                            uint16_t vlen)
{
    output += "\nstruct " + std::string(struct_name) + " {\n";
}

void
c_struct_define_generator::exit_struct_def(std::string &output,
                                           const char *struct_name)
{
    output += "} __attribute__((packed));\n";
}

void
c_struct_define_generator::define_new_field(std::string &output,
                                            field_info info)
{
}

void
c_struct_define_generator::enter_struct_field(std::string &output,
                                              field_info info)
{
    if (info.bit_sz != 0) {
        std::cerr << "bitfield not supported" << std::endl;
        throw std::runtime_error("bitfield not supported");
    }
    define_new_field(output, info);
}

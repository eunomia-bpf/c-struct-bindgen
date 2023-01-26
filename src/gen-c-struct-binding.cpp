
#include <string>
#include <vector>
#include <iostream>
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

int
binding_generator_base::walk_struct_for_id(std::string &output, int type_id)
{
    DECLARE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts, opts, .field_name = "",
                        .indent_level = 2, );
    struct btf_dump *d =
        btf_dump__new(btf_data, btf_dump_event_printf, NULL, NULL);
    auto t = btf__type_by_id(btf_data, type_id);
    if (!t) {
        std::cerr << "type id " << type_id << " not found" << std::endl;
        return -1;
    }
    auto struct_name = btf__name_by_offset(btf_data, t->name_off);
    if (!btf_is_struct(t)) {
        std::cerr << "type id " << type_id << " is not a struct" << std::endl;
        return -1;
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
        else {
            int err = get_btf_type_str(member_type_id, btf_data, type_str);
            if (err < 0) {
                std::cerr << "failed to get type string" << std::endl;
                return err;
            }
        }
        enter_struct_field(output, member_name, type_str.c_str(),
                           field_type_name.c_str(), bit_off, size, bit_sz);
    }
    exit_struct_def(output, struct_name);
    return 0;
}

void
c_struct_binding_generator::start_generate(std::string &output)
{
    std::string upper_name;
    std::transform(name.begin(), name.end(), std::back_inserter(upper_name),
                   ::toupper);

    const char *header_format = R"(
    // Generated by ecc -
    #ifndef __STRUCT_MARSHAL_%s_H__
    #define __STRUCT_MARSHAL_%s_H__

    #include <string.h>
    #include <stdint.h>
    
    )";
    char header[1024];
    snprintf(header, sizeof(header), header_format, upper_name.c_str(),
             upper_name.c_str());
    output += header;
}

void
c_struct_binding_generator::end_generate(std::string &output)
{
    std::string footer = R"(
    #endif
    )";
    output += footer;
}

void
c_struct_binding_generator::enter_struct_def(std::string &output,
                                             const char *struct_name,
                                             uint16_t vlen)
{
}
void
c_struct_binding_generator::exit_struct_def(std::string &output,
                                            const char *struct_name)
{
}
void
c_struct_binding_generator::enter_struct_field(std::string &output,
                                               const char *field_name,
                                               const char *field_type,
                                               const char *field_type_name,
                                               uint32_t bit_off, uint32_t size,
                                               uint32_t bit_sz)
{
}
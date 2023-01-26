
#include <string>
#include <vector>
#include <iostream>
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
    auto printer = static_cast<binding_generator::sprintf_printer *>(ctx);
    printer->vsprintf_event(fmt, args);
}

int
binding_generator::sprintf_printer::vsprintf_event(const char *fmt,
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
binding_generator::sprintf_printer::snprintf_event(size_t __maxlen,
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
binding_generator::sprintf_printer::sprintf_event(const char *fmt, ...)
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
    binding_generator::sprintf_printer printer;
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

int
binding_generator::walk_struct_for_id(std::string &output, int type_id)
{
    DECLARE_LIBBPF_OPTS(btf_dump_emit_type_decl_opts, opts, .field_name = "",
                        .indent_level = 2, );
    struct btf_dump *d =
        btf_dump__new(btf_data.get(), btf_dump_event_printf, NULL, NULL);
    auto t = btf__type_by_id(btf_data.get(), type_id);
    if (!t) {
        std::cerr << "type id " << type_id << " not found" << std::endl;
        return -1;
    }
    auto type_name = btf__name_by_offset(btf_data.get(), t->name_off);
    if (!btf_is_struct(t)) {
        std::cerr << "type id " << type_id << " is not a struct" << std::endl;
        return -1;
    }
    btf_member *m = btf_members(t);
    __u16 vlen = BTF_INFO_VLEN(t->info);
    std::cout << "type id: " << type_id << " name: " << type_name
              << " vlen: " << vlen << std::endl;
    for (size_t i = 0; i < vlen; i++, m++) {
        // found btf type id
        const char *member_name =
            btf__name_by_offset(btf_data.get(), m->name_off);
        auto member_type_id = m->type;
        uint32_t bit_off, bit_sz;
        std::string type_str;
        if (BTF_INFO_KFLAG(t->info)) {
            bit_off = BTF_MEMBER_BIT_OFFSET(m->offset);
            bit_sz = BTF_MEMBER_BITFIELD_SIZE(m->offset);
        }
        else {
            bit_off = m->offset;
            bit_sz = 0;
        }
        if (btf_is_composite(btf__type_by_id(btf_data.get(), m->type))) {
            std::cerr << "composite type is not supported" << std::endl;
            type_str = "composite";
        }
        else if (btf_is_enum(btf__type_by_id(btf_data.get(), m->type))) {
            std::cerr << "enum type is not supported" << std::endl;
            type_str = "enum";
        }
        else {
            int err =
                get_btf_type_str(member_type_id, btf_data.get(), type_str);
            if (err < 0) {
                std::cerr << "failed to get type string" << std::endl;
                return err;
            }
        }
        std::cout << "type id: " << member_type_id << " name: " << member_name
                  << " type: " << type_str << " offset: " << bit_off
                  << " size: " << bit_sz << std::endl;
    }
    return 0;
}

//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
#ifndef EUNOMIA_BINDING_GENERATOR_HPP_
#define EUNOMIA_BINDING_GENERATOR_HPP_

#include <functional>
#include <memory>
#include <vector>
#include <cstdio>
#include <cstdlib>
#include <iostream>
#include <cstdint>
#include "config.h"

extern "C" {
struct btf;
struct btf_type;
struct btf_dump;
void
btf__free(struct btf *btf);
void
btf_dump__free(struct btf_dump *d);
}

namespace eunomia {

class binding_generator_base
{
    void walk_all_structs(std::string &output);
    void walk_struct_for_id(std::string &output, int type_id);

  public:
    class sprintf_printer
    {
      public:
        static const std::size_t EVENT_SIZE = 512;
        std::string buffer;
        void reset(std::size_t size = 2048)
        {
            buffer.reserve(size);
            buffer.clear();
        }
        int printf(const char *fmt, ...);
        int snprintf_event(size_t __maxlen, const char *fmt, ...);
        int vprintf(const char *fmt, va_list args);
    };
    binding_generator_base(btf *object_btf_info, config &c);
    binding_generator_base(binding_generator_base &) = delete;
    binding_generator_base(binding_generator_base &&) = delete;
    binding_generator_base &operator=(binding_generator_base &) = delete;
    binding_generator_base &operator=(binding_generator_base &&) = delete;
    virtual ~binding_generator_base() = default;

    void generate_for_all_structs(std::string &output);
    struct field_info {
        size_t index;
        uint32_t type_id;
        const char *field_name;
        const char *field_type;
        const char *field_type_name;
        uint32_t bit_off;
        uint32_t size;
        uint32_t bit_sz;
    };
    struct struct_info {
        int type_id;
        uint32_t size;
        const char *struct_name;
        uint16_t vlen;
    };

  protected:
    std::unique_ptr<btf_dump, void (*)(btf_dump *)> btf_dumper{
        nullptr, btf_dump__free
    };
    sprintf_printer default_printer;
    btf *btf_data;
    size_t walk_count;
    size_t max_walk_count = 1;
    config generator_config;

    std::string get_c_file_header();
    std::string get_c_file_footer();

    virtual void enter_struct_def(std::string &output, struct_info info) = 0;
    virtual void exit_struct_def(std::string &output, struct_info info) = 0;
    virtual void enter_struct_field(std::string &output, field_info info) = 0;
    virtual void start_generate(std::string &output){};
    virtual void end_generate(std::string &output){};
};

class debug_binding_generator : public binding_generator_base
{
  public:
    debug_binding_generator(btf *btf_data_info, config &c)
      : binding_generator_base(btf_data_info, c)
    {
    }
    void enter_struct_def(std::string &output, struct_info info) override
    {
        std::cout << "enter struct " << info.struct_name << " vlen" << info.vlen
                  << std::endl;
    }
    void exit_struct_def(std::string &output, struct_info info) override
    {
        std::cout << "exit struct " << info.struct_name << std::endl;
    }
    void enter_struct_field(std::string &output, field_info info) override
    {
        std::cout << "enter field " << info.field_name << " type "
                  << info.field_type << " type name " << info.field_type_name
                  << " bit off " << info.bit_off << " size " << info.size
                  << " bit sz " << info.bit_sz << std::endl;
    }
};

class c_struct_marshal_generator : public binding_generator_base
{
    void marshal_field(std::string &output, field_info info);
    void unmarshal_field(std::string &output, field_info info);

  public:
    c_struct_marshal_generator(btf *btf_data_info, config &c)
      : binding_generator_base(btf_data_info, c)
    {
        max_walk_count = 2;
    }
    void start_generate(std::string &output) override;
    void end_generate(std::string &output) override;
    void enter_struct_def(std::string &output, struct_info info) override;
    void exit_struct_def(std::string &output, struct_info info) override;
    void enter_struct_field(std::string &output, field_info info) override;
};

class c_struct_define_generator : public binding_generator_base
{
    void define_new_field(std::string &output, field_info info);
    unsigned int off = 0, pad_cnt = 0, struct_vlen;

  public:
    c_struct_define_generator(btf *btf_data_info, config &c)
      : binding_generator_base(btf_data_info, c)
    {
        max_walk_count = 1;
    }
    void start_generate(std::string &output) override;
    void end_generate(std::string &output) override;
    void enter_struct_def(std::string &output, struct_info info) override;
    void exit_struct_def(std::string &output, struct_info info) override;
    void enter_struct_field(std::string &output, field_info info) override;
};

class c_struct_json_generator : public binding_generator_base
{
    void marshal_json_array(std::string& output,
                            const char* field_name,
                            int type_id,
                            const char* base_json_name,
                            bool base_json_is_array,
                            sprintf_printer& curr_printer,
                            const char* base_json_field_name,
                            int dim = 0);
    void unmarshal_json_array(std::string& output,
                            const char* field_name,
                            int type_id,
                            sprintf_printer& curr_printer,
                            const char* base_json_array_var_name,
                            int dim = 0);
    
    void marshal_json_type(std::string &output, field_info info,
                           const char *json_type_str,
                           const char *type_conversion,
                           const char *base_json_name, bool is_array);
    void marshal_json_struct(std::string &output, field_info info,
                             const char *base_json_name);
    void unmarshal_json_type(std::string &output, field_info info,
                             const char *json_type_str,
                             const char *type_conversion,
                             const char *base_json_name,
                             const char *value_type_str);
    void marshal_field(std::string &output, field_info info);
    void unmarshal_field(std::string &output, field_info info);

  public:
    c_struct_json_generator(btf *btf_data_info, config &c)
      : binding_generator_base(btf_data_info, c)
    {
        max_walk_count = 2;
    }
    void start_generate(std::string &output) override;
    void end_generate(std::string &output) override;
    void enter_struct_def(std::string &output, struct_info info) override;
    void exit_struct_def(std::string &output, struct_info info) override;
    void enter_struct_field(std::string &output, field_info info) override;
};

} // namespace eunomia

#endif // EUNOMIA_BINDING_GENERATOR_HPP_

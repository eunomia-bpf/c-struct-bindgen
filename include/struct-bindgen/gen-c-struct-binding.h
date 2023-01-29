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
    std::unique_ptr<btf_dump, void (*)(btf_dump *)> btf_dumper{
        nullptr, btf_dump__free
    };
    btf *btf_data;
    void walk_all_structs(std::string &output);
    void walk_struct_for_id(std::string &output, int type_id);

  protected:
    size_t walk_count;
    size_t max_walk_count = 1;
    config generator_config;

    std::string get_c_file_header();
    std::string get_c_file_footer();

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
        int sprintf_event(const char *fmt, ...);
        int snprintf_event(size_t __maxlen, const char *fmt, ...);
        int vsprintf_event(const char *fmt, va_list args);
    };
    binding_generator_base(btf *object_btf_info, config &c)
    {
        this->btf_data = object_btf_info;
        this->generator_config = c;
    }
    binding_generator_base(binding_generator_base &) = delete;
    binding_generator_base(binding_generator_base &&) = delete;
    binding_generator_base &operator=(binding_generator_base &) = delete;
    binding_generator_base &operator=(binding_generator_base &&) = delete;
    virtual ~binding_generator_base() = default;

    void generate_for_all_structs(std::string &output);

    virtual void enter_struct_def(std::string &output, const char *struct_name,
                                  uint16_t vlen) = 0;
    virtual void exit_struct_def(std::string &output,
                                 const char *struct_name) = 0;
    struct field_info {
        uint32_t type_id;
        const char *field_name;
        const char *field_type;
        const char *field_type_name;
        uint32_t bit_off;
        uint32_t size;
        uint32_t bit_sz;
    };
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
    void enter_struct_def(std::string &output, const char *struct_name,
                          uint16_t vlen) override
    {
        std::cout << "enter struct " << struct_name << " vlen" << vlen
                  << std::endl;
    }
    void exit_struct_def(std::string &output, const char *struct_name) override
    {
        std::cout << "exit struct " << struct_name << std::endl;
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
    void enter_struct_def(std::string &output, const char *struct_name,
                          uint16_t vlen) override;
    void exit_struct_def(std::string &output, const char *struct_name) override;
    void enter_struct_field(std::string &output, field_info info) override;
};

class c_struct_define_generator : public binding_generator_base
{
    void define_new_field(std::string &output, field_info info);

  public:
    c_struct_define_generator(btf *btf_data_info, config &c)
      : binding_generator_base(btf_data_info, c)
    {
        max_walk_count = 1;
    }
    void start_generate(std::string &output) override;
    void end_generate(std::string &output) override;
    void enter_struct_def(std::string &output, const char *struct_name,
                          uint16_t vlen) override;
    void exit_struct_def(std::string &output, const char *struct_name) override;
    void enter_struct_field(std::string &output, field_info info) override;
};

class c_struct_json_generator : public binding_generator_base
{
    void marshal_field(std::string &output, field_info info);
    void unmarshal_field(std::string &output, field_info info);

  public:
    c_struct_json_generator(btf *btf_data_info, config &c)
      : binding_generator_base(btf_data_info, c)
    {
        max_walk_count = 1;
    }
    void start_generate(std::string &output) override;
    void end_generate(std::string &output) override;
    void enter_struct_def(std::string &output, const char *struct_name,
                          uint16_t vlen) override;
    void exit_struct_def(std::string &output, const char *struct_name) override;
    void enter_struct_field(std::string &output, field_info info) override;
};

} // namespace eunomia

#endif // EUNOMIA_BINDING_GENERATOR_HPP_

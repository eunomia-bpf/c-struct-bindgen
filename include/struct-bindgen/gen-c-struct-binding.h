#ifndef EUNOMIA_BINDING_GENERATOR_HPP_
#define EUNOMIA_BINDING_GENERATOR_HPP_

#include <functional>
#include <memory>
#include <vector>

#include <cstdio>
#include <cstdlib>

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
    binding_generator_base(btf *object_btf_info)
    {
        this->btf_data = object_btf_info;
    }
    binding_generator_base(binding_generator_base &) = delete;
    binding_generator_base(binding_generator_base &&) = delete;
    binding_generator_base &operator=(binding_generator_base &) = delete;
    binding_generator_base &operator=(binding_generator_base &&) = delete;
    virtual ~binding_generator_base() = default;
    int walk_struct_for_id(std::string &output, int type_id);
    int generate_for_all_structs(std::string &output);
    virtual int enter_struct_def(std::string &output,
                                 const char *struct_name) = 0;
    virtual int leave_struct_def(std::string &output,
                                 const char *struct_name) = 0;
    virtual int enter_struct_field(std::string &output, const char *field_name,
                                   const char *field_type,
                                   const char *field_type_name) = 0;
};

class c_struct_binding_generator : public binding_generator_base
{
  public:
    c_struct_binding_generator(btf *btf_data)
      : binding_generator_base(btf_data)
    {
    }
    int enter_struct_def(std::string &output, const char *struct_name) override;
    int leave_struct_def(std::string &output, const char *struct_name) override;
    int enter_struct_field(std::string &output, const char *field_name,
                           const char *field_type,
                           const char *field_type_name) override;
};

} // namespace eunomia

#endif // EUNOMIA_BINDING_GENERATOR_HPP_

#ifndef EUNOMIA_EXPORT_EVENTS_HPP_
#define EUNOMIA_EXPORT_EVENTS_HPP_

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
/// @brief dump export event in user space
class binding_generator
{
    std::unique_ptr<btf_dump, void (*)(btf_dump *)> btf_dumper{
        nullptr, btf_dump__free
    };
    std::unique_ptr<btf, void (*)(btf *)> btf_data{ nullptr, btf__free };

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
    binding_generator(btf *btf_data)
    {
        this->btf_data =
            std::unique_ptr<btf, void (*)(btf *)>(btf_data, btf__free);
    }
    int walk_struct_for_id(std::string &output, int type_id);
};

} // namespace eunomia

#endif // EUNOMIA_EXPORT_EVENTS_HPP_
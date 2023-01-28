# struct-bindgen

A tool for generate marshal and unmarshal functions for C structs using BTF info. This tool can be use to:

- generate functions bindings for passing c struct from ebpf programs and host environments, to wasm runtime: see [eunomia-bpf](https://github.com/eunomia-bpf/eunomia-bpf) project.
- generate marshal and unmarshal functions for convert C structs to JSON format.

## Usage - Genereate Struct to Struct binding func

See `examples/` for [examples](examples).

1. Create a `C` header to define a `C` struct, for example:

    examples/test-event.h:

    ```c
    #ifndef __SIGSNOOP_H
    #define __SIGSNOOP_H

    struct event2 {
        void* unused_ptr;
        float x;
        double y;
        int z;
        long long int a;
        short comm[16];
    };

    #endif /* __SIGSNOOP_H */
    ```

    The number of structs, names of structs are not limited. Struct fields can be any valid C types, including structs, unions, arrays, pointers, etc.

2. Generate bindings:

    ```bash
    ecc examples/test-event.h --header-only
    struct-bindgen examples/source.bpf.o
    ```

    You will get a `source-struct-binding.h` file, for example:

    ```c
    // Code generated by c-struct-bindgen and ecc - DO NOT EDIT
    // See https://github.com/eunomia-bpf/c-struct-bindgen for details.
    // struct-bindgen versions: 0.1.0
    // source file path: /home/yunwei/c-struct-bindgen/examples/source.bpf.o
    #ifndef __STRUCT_MARSHAL_SOURCE_BPF_O_H__
    #define __STRUCT_MARSHAL_SOURCE_BPF_O_H__
        
    #include <assert.h>
    #include <string.h>
    #include <stdint.h>

    static void marshal_struct_event__to_binary(void *dst, const struct event *src) {
        assert(dst && src);
        *(unsigned long long*)(dst + 0) = src->ts;
        *(int*)(dst + 8) = src->pid;
        *(int*)(dst + 12) = src->uid;
        *(int*)(dst + 16) = src->ret;
        *(int*)(dst + 20) = src->flags;
        memcpy(dst + 24, src->comm, 16);
    }

    static void unmarshal_struct_event__from_binary(struct event *dst, const void *src) {
        assert(dst && src);
        dst->ts = *(unsigned long long*)(src + 0);
        dst->pid = *(int*)(src + 8);
        dst->uid = *(int*)(src + 12);
        dst->ret = *(int*)(src + 16);
        dst->flags = *(int*)(src + 20);
        memcpy(dst->comm, src + 24, 16);
    }
    #endif
    ```

## Usage - From pre-compiled bpf object with BTF info

```bash
struct-bindgen examples/source.bpf.o
```

You will get a `source-struct-binding.h` file, for correct access to the C struct memory in the bpf programs or host env.

## Download Pre-build Release

Download ecc:

```console
$ wget https://github.com/eunomia-bpf/eunomia-bpf/releases/latest/download/ecc && chmod +x ./ecc
$ ./ecc -h
eunomia-bpf compiler
Usage: ecc [OPTIONS] <SOURCE_PATH> [EXPORT_EVENT_HEADER]
```

Download struct-bindgen:

```console

```

## build

This tool relies on libbpf.

### Install Dependencies

This tool relies on libbpf. You will need `clang`, `libelf` and `zlib` to build the examples, package names may vary across distros.

On Ubuntu/Debian, you need:

```shell
apt install clang libelf1 libelf-dev zlib1g-dev
```

On CentOS/Fedora, you need:

```shell
dnf install clang elfutils-libelf elfutils-libelf-devel zlib-devel
```

### build executable

```sh
make
```

The binary can be found in 

## Roadmap

- [X] Support for generate C struct marshal functions in C
- [ ] Support for union in structs fields
- [ ] Support for composite types in array fields
- [ ] handle byte order in host env
- [ ] Support for print out info in JSON format

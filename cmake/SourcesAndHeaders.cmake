set(sources
    src/bpf_object_reader.cpp
    src/gen-c-struct-binding.cpp
    src/gen-json-binding.cpp
)

set(exe_sources
		src/main.cpp
		${sources}
)

set(headers
    include/
)

EXECUTE_PROCESS( COMMAND uname -m COMMAND tr -d '\n' OUTPUT_VARIABLE ARCHITECTURE )

set(third_party_headers
    libbpf/include/uapi
    libbpf/
)

set(test_sources
    src/bpf_object_reader_test.cpp
    src/marshal_struct_test.cpp
    src/generate_c_struct_binding_test.cpp
    src/marshal_json_test.cpp
)

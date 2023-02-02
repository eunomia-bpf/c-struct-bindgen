//!  SPDX-License-Identifier: MIT
//!
//! Copyright (c) 2023, eunomia-bpf
//! All rights reserved.
//!
#include <string>
#include <vector>
#include <iostream>
#include <algorithm>
#include <cstring>
#include "struct-bindgen/gen-c-struct-binding.h"
#include <sstream>

extern "C" {
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <bpf/btf.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <assert.h>
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
#include "cJSON.h"
#ifndef _DEC_STR_CONV_DECL
#define _DEC_STR_CONV_DECL

#include <stdlib.h>

static unsigned long long str2dec(const char* str) {
    unsigned long long ret = 0;
    while (*str) {
        ret = ret * 10 + (*str - '0');
        str++;
    }
    return ret;
}
static char* dec2str(unsigned long long x) {
    int digcnt = 0;
    {
        unsigned long long t = x;
        if (t == 0) {
            digcnt = 1;
        } else {
            while (t) {
                digcnt++;
                t /= 10;
            }
        }
    }
    char* ret = (char*)malloc(digcnt + 1);
    ret[digcnt] = '\0';
    if (x == 0) {
        ret[0] = '0';
    } else {
        int cursor = digcnt - 1;

        while (x) {
            ret[cursor] = (x % 10) + '0';
            x /= 10;
            cursor--;
        }
    }
    return ret;
}
#endif

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
static char *
marshal_struct_%s__to_json_str(const struct %s *src)
{
    assert(src);
    cJSON *object = cJSON_CreateObject();
    if (!object) {
        return NULL;
    }
)";
        char struct_def[BUFFER_SIZE];
        snprintf(struct_def, sizeof(struct_def), function_proto,
                 info.struct_name, info.struct_name);
        output += struct_def;
    }
    else {
        // generate unmarshal function
        const char *function_proto = R"(
static struct %s *
unmarshal_struct_%s__from_json_str(struct %s *dst, const char *src)
{
    assert(dst && src);
    cJSON *object = cJSON_Parse(src);
    if (!object) {
        return NULL;
    }
)";
        char struct_def[BUFFER_SIZE];
        snprintf(struct_def, sizeof(struct_def), function_proto,
                 info.struct_name, info.struct_name, info.struct_name);
        output += struct_def;
    }
}

void
c_struct_json_generator::exit_struct_def(std::string &output, struct_info info)
{
    if (walk_count == 0) {
        // generate marshal function
        output = output + R"(
    char* result_val = cJSON_PrintUnformatted(object);
    cJSON_Delete(object);
    return result_val;
)";
    }
    else {
        // generate unmarshal function
        output = output + R"(
    cJSON_Delete(object);
    return dst;
)";
    }
    output += "}\n";
}

void
c_struct_json_generator::marshal_json_struct(std::string &output,
                                             field_info info,
                                             const char *base_json_name)
{
    const char *format = R"(
    char *%s_object_str = marshal_struct_%s__to_json_str(&src->%s);
    if (!%s_object_str) {
        cJSON_Delete(%s);
        return NULL;
    }
    cJSON *%s_object = cJSON_Parse(%s_object_str);
    if (!%s_object) {
        cJSON_Delete(%s);
        return NULL;
    }
    if (!cJSON_AddItemToObject(object, "%s", %s_object)) {
        cJSON_Delete(%s);
        return NULL;
    }
    cJSON_free(%s_object_str);
)";
    default_printer.printf(format, info.field_name, info.field_type_name,
                           info.field_name, info.field_name, base_json_name,
                           info.field_name, info.field_name, info.field_name,
                           base_json_name, info.field_name, info.field_name,
                           base_json_name, info.field_name);
}

void
c_struct_json_generator::marshal_json_type(std::string &output, field_info info,
                                           const char *json_type_str,
                                           const char *type_conversion,
                                           const char *base_json_name,
                                           bool is_array)
{
    const char *format = R"(
    cJSON *%s_object = cJSON_Create%s(%ssrc->%s);
    if (!%s_object) {
        cJSON_Delete(%s);
        return NULL;
    }
    if (!cJSON_AddItemTo%s(object, "%s", %s_object)) {
        cJSON_Delete(%s);
        return NULL;
    }
)";
    const char *add_to = is_array ? "Array" : "Object";
    default_printer.printf(format, info.field_name, json_type_str,
                           type_conversion, info.field_name, info.field_name,
                           base_json_name, add_to, info.field_name,
                           info.field_name, base_json_name);
}

void
c_struct_json_generator::unmarshal_json_type(std::string &output,
                                             field_info info,
                                             const char *json_type_str,
                                             const char *type_conversion,
                                             const char *base_json_name,
                                             const char *value_type_str)
{
    const char *format = R"(
    cJSON *%s_object = cJSON_GetObjectItemCaseSensitive(object, "%s");
    if (!cJSON_Is%s(%s_object)) {
        cJSON_Delete(object);
        return NULL;
    }
    dst->%s = %s%s_object->%s;
)";
    default_printer.printf(format, info.field_name, info.field_name,
                           json_type_str, info.field_name, info.field_name,
                           type_conversion, info.field_name, value_type_str);
}

void
c_struct_json_generator::marshal_field(std::string &output, field_info info)
{
    uint32_t offset = info.bit_off / 8;
    default_printer.reset();
    auto var = btf__type_by_id(btf_data, info.type_id);

    if ((btf_is_int(var) && var->size <= 4) || btf_is_float(var)) {
        marshal_json_type(output, info, "Number", "", "object", false);

    } else if (btf_is_ptr(var) || (btf_is_int(var) && var->size > 4)) {
        default_printer.printf(R"(
            {
            char* str_final_elem = dec2str((long long int)src->%s);
            cJSON* final_elem = cJSON_CreateString(str_final_elem);
            free(str_final_elem);
            if (!final_elem) {
                return NULL;
            }
            if (!cJSON_AddItemToObject(object, "%s", final_elem)){
                return NULL;
            }
            }
        )",
                               info.field_name, info.field_name);
    } else

        if (btf_is_array(var)) {
        marshal_json_array(output, info.field_name, info.type_id, "object",
                           false, default_printer, info.field_name);
    } else if (btf_is_struct(var)) {
        marshal_json_struct(output, info, "object");
    } else if (btf_is_union(var)) {
        // TODO: add more type support
        throw std::runtime_error("union is not supported");
    } else {
        throw std::runtime_error("unknown type");
    }
    output += default_printer.buffer;
}

void
c_struct_json_generator::unmarshal_field(std::string &output, field_info info)
{
    uint32_t offset = info.bit_off / 8;
    default_printer.reset();
    auto var = btf__type_by_id(btf_data, info.type_id);
    if (btf_is_int(var) && var->size <= 4) {
        unmarshal_json_type(output, info, "Number", "", "object", "valuedouble");
    } 
    else if (btf_is_float(var)) {
        unmarshal_json_type(output, info, "Number", "", "object",
                            "valuedouble");
    } else if (btf_is_ptr(var) || (btf_is_int(var) && var->size > 4)) {
        char var_name[128];
        snprintf(var_name, sizeof(var_name), "%s_object", info.field_name);
        default_printer.printf(R"(
            cJSON *%s = cJSON_GetObjectItemCaseSensitive(object, "%s");
            if (!cJSON_IsString(%s)){
                return NULL;
            }
            dst->%s = %sstr2dec(%s->valuestring);
        )",
                               var_name, info.field_name, var_name,
                               info.field_name,
                               btf_is_ptr(var) ? "(void*)" : "", var_name);
    } else if (btf_is_array(var)) {
        unmarshal_json_array(output, info.field_name, info.type_id,
                             default_printer, nullptr);
    } else if (btf_is_struct(var)) {
        const char* format = R"(
    cJSON* %s_obj = cJSON_GetObjectItemCaseSensitive(object, "%s");
    if(!%s_obj) return NULL;
    char* %s_str = cJSON_PrintUnformatted(%s_obj);
    unmarshal_struct_%s__from_json_str(&dst->%s, %s_str);
    cJSON_free(%s_str);
        )";
        default_printer.printf(
            format, info.field_name, info.field_name, info.field_name,
            info.field_name, info.field_name, info.field_type_name, info.field_name, info.field_name, info.field_name);
    } else if (btf_is_union(var)) {
        throw std::runtime_error("union is not supported");
    } else {
        throw std::runtime_error("unknown type");
    }
    output += default_printer.buffer;
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

static std::string generate_dim_accessor(int dim) {
    std::ostringstream os;
    char buf[512];
    for (int i = 0; i <= dim; i++) {
        snprintf(buf, sizeof(buf), "[var_dim_%d]", i);
        os << buf;
    }
    return os.str();
}

void c_struct_json_generator::marshal_json_array(
    std::string& output,
    const char* field_name,
    int type_id,
    const char* base_json_name,
    bool base_json_is_array,
    sprintf_printer& curr_printer,
    const char* base_json_field_name,
    int dim) {
    using std::cerr;
    using std::endl;

    const btf_type* type_info = btf__type_by_id(btf_data, type_id);

    // cerr << "rec dim = " << dim << endl;
    // cerr << "field name=" << field_name << endl;
    // cerr << "base json name = " << base_json_name << endl;
    // cerr << "type=" << type_info->type << " size=" << type_info->size
    //      << " type_name=" << btf__name_by_offset(btf_data,
    //      type_info->name_off)
    //      << endl;
    assert(btf_is_array(type_info));
    const struct btf_array* array_info = btf_array(type_info);
    const struct btf_type* elem_type =
        btf__type_by_id(this->btf_data, array_info->type);

    char object_name[512];
    snprintf(object_name, sizeof(object_name), "%s_object_dim_%d", field_name,
             dim);
    curr_printer.printf("{");
    if (btf_is_int(elem_type) && elem_type->size == 1 && dim == 0) {
        // Special handle for strings
        curr_printer.printf(R"(
        cJSON* %s;
        {
            char buf[%d];
            int i = 0;
            for(;i < %d; i++) buf[i] = src -> %s [i];
            buf[%d] = '\0'; 
            %s = cJSON_CreateString(buf);

        }
    )",
                           object_name, array_info->nelems + 1, array_info->nelems,
                            field_name, array_info->nelems, object_name);
    } else {
        const char* format = R"(
    cJSON *%s = cJSON_CreateArray();
    if (!%s) {
        return NULL;
    }

)";
        curr_printer.printf(format, object_name, object_name);

        curr_printer.printf(
            "int var_dim_%d = 0;\nfor(; var_dim_%d < %d; var_dim_%d ++) {\n",
            dim, dim, array_info->nelems, dim);
        std::string index = generate_dim_accessor(dim);
        if (btf_is_array(elem_type)) {
            marshal_json_array(output, field_name, array_info->type,
                               object_name, true, curr_printer, nullptr,
                               dim + 1);
        } else if ((btf_is_int(elem_type) && elem_type->size <= 4) ||
                   btf_is_float(elem_type)) {
            //  Use Number to store smaller scalars and floatings
            default_printer.printf(
                R"(
            cJSON* final_elem = cJSON_CreateNumber(%s src -> %s %s );
            if (!final_elem) {
                return NULL;
            }
            if (!cJSON_AddItemToArray(%s, final_elem)){
                return NULL;
            }
        )",
                btf_is_ptr(elem_type) ? "(long long int)" : "", field_name,
                index.c_str(), object_name);
        } else if (btf_is_ptr(elem_type) ||
                   (btf_is_int(elem_type) && elem_type->size > 4)) {
            // Use store for larger scalars
            default_printer.printf(R"(
            char* str_final_elem = dec2str((long long int)src-> %s %s);
            cJSON* final_elem = cJSON_CreateString(str_final_elem);
            free(str_final_elem);
            if (!final_elem) {
                return NULL;
            }
            if (!cJSON_AddItemToArray(%s, final_elem)){
                return NULL;
            }
        )",
                                   field_name, index.c_str(), object_name);
        } else {
            // TODO: struct arrays
            throw std::runtime_error("Support for struct arrays is WIP");
        }
        curr_printer.printf("}\n");  // This bracket is for the for-loop
        }
        if (base_json_is_array) {
            curr_printer.printf(R"(
            if (!cJSON_AddItemToArray(%s, %s)) {
                return NULL;
            }
    )",
                                base_json_name, object_name, object_name);
        } else {
            curr_printer.printf(R"(
            if (!cJSON_AddItemToObject(%s, "%s", %s)) {
                return NULL;
            }
    )",
                                base_json_name, base_json_field_name,
                                object_name);
        }
        curr_printer.printf("}\n");
    
}

void c_struct_json_generator::unmarshal_json_array(
    std::string& output,
    const char* field_name,
    int type_id,
    sprintf_printer& curr_printer,
    const char* base_json_array_var_name,
    int dim) {
    using std::cerr;
    using std::endl;

    const btf_type* type_info = btf__type_by_id(btf_data, type_id);

    assert(btf_is_array(type_info));
    const struct btf_array* array_info = btf_array(type_info);
    const struct btf_type* elem_type =
        btf__type_by_id(this->btf_data, array_info->type);
    char top_var_name[128];
    snprintf(top_var_name, sizeof(top_var_name), "%s_object", field_name);
    base_json_array_var_name = top_var_name;
    if (dim == 0) {
            // The top dimension
            curr_printer.printf(R"(
            cJSON* %s = cJSON_GetObjectItemCaseSensitive(object, "%s");
            if (!%s) return NULL;

        )",
                                top_var_name, field_name, top_var_name);
    }
    curr_printer.printf("{");
    if (btf_is_int(elem_type) && elem_type->size == 1 && dim == 0) {
            curr_printer.printf(R"(
            if(!cJSON_IsString(%s)) return NULL;
            strncpy(dst -> %s, %s -> valuestring, %d);
        )",
                                top_var_name, field_name, top_var_name,
                                array_info->nelems);
    } else {
            curr_printer.printf(R"(
     if (!cJSON_IsArray(%s)) {
         return NULL;
     }

 )",
                                base_json_array_var_name);
            char for_each_var_name[128];
            snprintf(for_each_var_name, sizeof(for_each_var_name),
                     "var_iter_dim_%d", dim);
            curr_printer.printf("int var_dim_%d = 0;\n", dim);
            curr_printer.printf("cJSON* %s;\n", for_each_var_name);

            curr_printer.printf("cJSON_ArrayForEach(%s, %s) {",
                                for_each_var_name, base_json_array_var_name);
            std::string index = generate_dim_accessor(dim);

            if (btf_is_array(elem_type)) {
            // If the next dim is still array, then recursive
            unmarshal_json_array(output, field_name, array_info->type,
                                 curr_printer, for_each_var_name, dim + 1);
            } else if ((btf_is_int(elem_type) && elem_type->size <= 4) ||
                       btf_is_float(elem_type)) {
            //  Use Number to store integer less than 4byte and floats
            default_printer.printf(R"(
            if (!cJSON_IsNumber(%s)){
                return NULL;
            }
            dst->%s%s = %s->valuedouble;
        )",
                                   for_each_var_name, field_name, index.c_str(),
                                   for_each_var_name);
            } else if (btf_is_ptr(elem_type) ||
                       (btf_is_int(elem_type) && elem_type->size > 4)) {
            // Use string to store pointers and integers larger than 4byte
            default_printer.printf(R"(
            if (!cJSON_IsString(%s)){
                return NULL;
            }
            dst->%s%s = str2dec(%s->valuestring);
        )",
                                   for_each_var_name, field_name, index.c_str(),
                                   for_each_var_name);
            } else {
            // TODO: struct arrays
            throw std::runtime_error("Support for struct arrays is WIP");
            }
            curr_printer.printf("var_dim_%d ++;\n", dim);
            curr_printer.printf("}\n");  // This bracket is for the for-loop
    }
    curr_printer.printf("}\n");
}
#ifndef __C_STRUCT_BINDING_GENERATOR_CONFIG_H__
#define __C_STRUCT_BINDING_GENERATOR_CONFIG_H__

#include <string>

/// @brief  Configuration for the generator
struct config {
    /// @brief Use #pragma once instead of include guards
    bool use_pragma_once = false;
    /// @brief Path of source file
    std::string source_file_path;
};

#ifndef EUNOMIA_VERSION
#define EUNOMIA_VERSION "0.1.0"
#endif

#endif

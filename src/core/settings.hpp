#pragma once

#include <fstream>

#include "src/core/types.hpp"

namespace ucsb {

struct settings_t {
    std::string db_name;
    std::string workload_filter;

    fs::path db_config_file_path;
    fs::path db_main_dir_path;
    std::vector<fs::path> db_storage_dir_paths;

    fs::path workloads_file_path;
    fs::path results_file_path;

    size_t threads_count = 1;
    bool transactional = false;
};

} // namespace ucsb
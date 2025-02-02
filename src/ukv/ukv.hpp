#pragma once

#include <cassert>
#include <string>
#include <fstream>
#include <streambuf>

#include <ustore/ustore.h>
#include <ustore/cpp/status.hpp>
#include <ustore/cpp/types.hpp>
#include <helpers/config_loader.hpp>

#include "src/core/db.hpp"
#include "src/core/helper.hpp"
#include "src/core/types.hpp"

#include "ukv_transaction.hpp"

namespace ucsb::ukv {

namespace fs = ucsb::fs;
namespace ukv = unum::ustore;

using key_t = ucsb::key_t;
using keys_spanc_t = ucsb::keys_spanc_t;
using value_span_t = ucsb::value_span_t;
using value_spanc_t = ucsb::value_spanc_t;
using values_span_t = ucsb::values_span_t;
using values_spanc_t = ucsb::values_spanc_t;
using value_lengths_spanc_t = ucsb::value_lengths_spanc_t;
using operation_status_t = ucsb::operation_status_t;
using operation_result_t = ucsb::operation_result_t;
using db_hints_t = ucsb::db_hints_t;
using transaction_t = ucsb::transaction_t;

thread_local ukv::arena_t arena(nullptr);

class ustore_t : public ucsb::db_t {
  public:
    inline ustore_t() : db_(nullptr) {}
    ~ustore_t() { free(); }
    void set_config(fs::path const& config_path,
                    fs::path const& main_dir_path,
                    std::vector<fs::path> const& storage_dir_paths,
                    db_hints_t const& hints) override;
    bool open(std::string& error) override;
    void close() override;

    std::string info() override;

    operation_result_t upsert(key_t key, value_spanc_t value) override;
    operation_result_t update(key_t key, value_spanc_t value) override;
    operation_result_t remove(key_t key) override;
    operation_result_t read(key_t key, value_span_t value) const override;

    operation_result_t batch_upsert(keys_spanc_t keys, values_spanc_t values, value_lengths_spanc_t sizes) override;
    operation_result_t batch_read(keys_spanc_t keys, values_span_t values) const override;

    operation_result_t bulk_load(keys_spanc_t keys, values_spanc_t values, value_lengths_spanc_t sizes) override;

    operation_result_t range_select(key_t key, size_t length, values_span_t values) const override;
    operation_result_t scan(key_t key, size_t length, value_span_t single_value) const override;

    void flush() override;

    size_t size_on_disk() const override;

    std::unique_ptr<transaction_t> create_transaction() override;

  private:
    void free();

    fs::path config_path_;
    fs::path main_dir_path_;
    std::vector<fs::path> storage_dir_paths_;
    db_hints_t hints_;

    ustore_database_t db_;
    ustore_collection_t collection_ = ustore_collection_main_k;
    ustore_options_t options_ = ustore_options_default_k;
};

void ustore_t::set_config(fs::path const& config_path,
                       fs::path const& main_dir_path,
                       std::vector<fs::path> const& storage_dir_paths,
                       db_hints_t const& hints) {
    config_path_ = config_path;
    main_dir_path_ = main_dir_path;
    storage_dir_paths_ = storage_dir_paths;
    hints_ = hints;
}

bool ustore_t::open(std::string& error) {
    if (db_)
        return true;

    // Read config from file
    std::ifstream stream(config_path_);
    if (!stream) {
        error = strerror(errno);
        return false;
    }
    std::string str_config((std::istreambuf_iterator<char>(stream)), std::istreambuf_iterator<char>());

    // Load and overwrite
    ukv::config_t config;
    auto status = ukv::config_loader_t::load_from_json_string(str_config, config, true);
    if (!status) {
        error = status.message();
        return false;
    }

    // Resolve directory paths
    if (config.directory.empty())
        config.directory = main_dir_path_;
    if (config.data_directories.empty()) {
#if defined(UKV_ENGINE_IS_ROCKSDB)
        for (auto const& dir : storage_dir_paths_) {
            size_t storage_size_on_disk = (hints_.records_count * hints_.value_length) / storage_dir_paths_.size();
            config.data_directories.push_back({dir, storage_size_on_disk});
        }
#else
        for (auto const& dir : storage_dir_paths_)
            config.data_directories.push_back({dir, ukv::disk_config_t::unlimited_space_k});
#endif
    }

    // Resolve engine config path
    if (config.engine.config_file_path.empty()) {
        auto configs_root = config_path_.parent_path().parent_path();
        if (configs_root.filename() != "configs") {
            error = "Invalid configs directory";
            return false;
        }
        config.engine.config_file_path = configs_root / UKV_ENGINE_NAME / config_path_.filename();
        // Select default config if the specified doesn't exist
        if (!fs::exists(config.engine.config_file_path))
            config.engine.config_file_path = fs::path(config.engine.config_file_path).parent_path() / "default.cfg";
    }

    // Convert to json string
    status = ukv::config_loader_t::save_to_json_string(config, str_config);
    if (!status) {
        error = status.message();
        return false;
    }

    ustore_database_init_t init {};
    init.config = str_config.c_str();
#if defined(UKV_ENGINE_IS_FLIGHT_CLIENT)
    init.config = "grpc://0.0.0.0:38709";
#endif
    init.db = &db_;
    init.error = status.member_ptr();
    ustore_database_init(&init);
    if (!status) {
        error = status.message();
        return status;
    }

    arena = ukv::arena_t(db_);
    return true;
}

void ustore_t::close() {
#if !defined(UKV_ENGINE_IS_UMEM)
    free();
#endif
}

void ustore_t::free() {
    ustore_database_free(db_);
    db_ = nullptr;
}

operation_result_t ustore_t::upsert(key_t key, value_spanc_t value) {
    ukv::status_t status;
    ustore_key_t key_ = key;
    ustore_length_t length = value.size();
    auto value_ = make_value(value.data(), value.size());

    ustore_write_t write {};
    write.db = db_;
    write.error = status.member_ptr();
    write.arena = arena.member_ptr();
    write.options = options_;
    write.tasks_count = 1;
    write.collections = &collection_;
    write.keys = &key_;
    write.lengths = reinterpret_cast<ustore_length_t const*>(&length);
    write.values = value_.member_ptr();
    ustore_write(&write);

    return {size_t(status), status ? operation_status_t::ok_k : operation_status_t::error_k};
}

operation_result_t ustore_t::update(key_t key, value_spanc_t value) {
    ukv::status_t status;
    ustore_key_t key_ = key;
    ustore_byte_t* value_ = nullptr;

    ustore_read_t read {};
    read.db = db_;
    read.error = status.member_ptr();
    read.arena = arena.member_ptr();
    read.options = options_;
    read.tasks_count = 1;
    read.collections = &collection_;
    read.keys = &key_;
    read.values = &value_;
    ustore_read(&read);
    if (!status)
        return {0, operation_status_t::not_found_k};

    return upsert(key, value);
}

operation_result_t ustore_t::remove(key_t key) {
    ukv::status_t status;
    ustore_key_t key_ = key;

    ustore_write_t write {};
    write.db = db_;
    write.error = status.member_ptr();
    write.arena = arena.member_ptr();
    write.options = options_;
    write.tasks_count = 1;
    write.collections = &collection_;
    write.keys = &key_;
    ustore_write(&write);

    return {status ? size_t(1) : 0, status ? operation_status_t::ok_k : operation_status_t::error_k};
}

operation_result_t ustore_t::read(key_t key, value_span_t value) const {
    ukv::status_t status;
    ustore_key_t key_ = key;
    ustore_byte_t* value_ = nullptr;
    ustore_length_t* lengths = nullptr;

    ustore_read_t read {};
    read.db = db_;
    read.error = status.member_ptr();
    read.arena = arena.member_ptr();
    read.options = options_;
    read.tasks_count = 1;
    read.collections = &collection_;
    read.keys = &key_;
    read.lengths = &lengths;
    read.values = &value_;
    ustore_read(&read);
    if (!status)
        return {0, operation_status_t::error_k};
    if (lengths[0] == ustore_length_missing_k)
        return {0, operation_status_t::not_found_k};

    memcpy(value.data(), value_, lengths[0]);
    return {1, operation_status_t::ok_k};
}

operation_result_t ustore_t::batch_upsert(keys_spanc_t keys, values_spanc_t values, value_lengths_spanc_t sizes) {
    ukv::status_t status;
    std::vector<ustore_length_t> offsets;
    offsets.reserve(sizes.size() + 1);
    offsets.push_back(0);
    for (auto size : sizes)
        offsets.push_back(offsets.back() + size);

    auto values_ = make_value(values.data(), values.size());
    ustore_write_t write {};
    write.db = db_;
    write.error = status.member_ptr();
    write.arena = arena.member_ptr();
    write.options = options_;
    write.tasks_count = keys.size();
    write.collections = &collection_;
    write.keys = reinterpret_cast<ustore_key_t const*>(keys.data());
    write.keys_stride = sizeof(ustore_key_t);
    write.offsets = offsets.data();
    write.offsets_stride = sizeof(ustore_length_t);
    write.lengths = reinterpret_cast<ustore_length_t const*>(sizes.data());
    write.lengths_stride = sizeof(ustore_length_t);
    write.values = values_.member_ptr();
    ustore_write(&write);

    return {status ? keys.size() : 0, status ? operation_status_t::ok_k : operation_status_t::error_k};
}

operation_result_t ustore_t::batch_read(keys_spanc_t keys, values_span_t values) const {
    ukv::status_t status;
    ustore_octet_t* presences = nullptr;
    ustore_length_t* offsets = nullptr;
    ustore_length_t* lengths = nullptr;
    ustore_byte_t* values_ = nullptr;

    ustore_read_t read {};
    read.db = db_;
    read.error = status.member_ptr();
    read.arena = arena.member_ptr();
    read.options = options_;
    read.tasks_count = keys.size();
    read.collections = &collection_;
    read.keys = reinterpret_cast<ustore_key_t const*>(keys.data());
    read.keys_stride = sizeof(ustore_key_t);
    read.presences = &presences;
    read.offsets = &offsets;
    read.lengths = &lengths;
    read.values = &values_;
    ustore_read(&read);
    if (!status)
        return {0, operation_status_t::error_k};

    size_t offset = 0;
    size_t found_cnt = 0;
    for (size_t idx = 0; idx < keys.size(); ++idx) {
        if (lengths[idx] == ustore_length_missing_k)
            continue;
        memcpy(values.data() + offset, values_ + offsets[idx], lengths[idx]);
        offset += lengths[idx];
        ++found_cnt;
    }

    return {found_cnt, found_cnt > 0 ? operation_status_t::ok_k : operation_status_t::not_found_k};
}

operation_result_t ustore_t::bulk_load(keys_spanc_t keys, values_spanc_t values, value_lengths_spanc_t sizes) {
    return batch_upsert(keys, values, sizes);
}

operation_result_t ustore_t::range_select(key_t key, size_t length, values_span_t values) const {
    ukv::status_t status;
    ustore_key_t key_ = key;
    ustore_length_t len = length;
    ustore_length_t* found_counts = nullptr;
    ustore_key_t* found_keys = nullptr;

    // First scan keys
    ustore_scan_t scan {};
    scan.db = db_;
    scan.error = status.member_ptr();
    scan.arena = arena.member_ptr();
    scan.options = options_;
    scan.tasks_count = 1;
    scan.collections = &collection_;
    scan.start_keys = &key_;
    scan.count_limits = &len;
    scan.counts = &found_counts;
    scan.keys = &found_keys;
    ustore_scan(&scan);
    if (!status)
        return {0, operation_status_t::error_k};

    ustore_length_t* offsets = nullptr;
    ustore_length_t* lengths = nullptr;
    ustore_byte_t* values_ = nullptr;

    // Then do batch read
    ustore_read_t read {};
    read.db = db_;
    read.error = status.member_ptr();
    read.arena = arena.member_ptr();
    read.options = ustore_options_t(options_ | ustore_option_dont_discard_memory_k);
    read.tasks_count = *found_counts;
    read.collections = &collection_;
    read.keys = found_keys;
    read.keys_stride = sizeof(ustore_key_t);
    read.offsets = &offsets;
    read.lengths = &lengths;
    read.values = &values_;
    ustore_read(&read);
    if (!status)
        return {0, operation_status_t::error_k};

    size_t offset = 0;
    for (size_t idx = 0; idx < *found_counts; ++idx) {
        if (lengths[idx] == ustore_length_missing_k)
            continue;
        memcpy(values.data() + offset, values_ + offsets[idx], lengths[idx]);
        offset += lengths[idx];
    }

    return {*found_counts, *found_counts > 0 ? operation_status_t::ok_k : operation_status_t::not_found_k};
}

operation_result_t ustore_t::scan(key_t key, size_t length, value_span_t single_value) const {
    ukv::status_t status;
    ustore_key_t key_ = key;
    ustore_length_t len =
        std::min<ustore_length_t>(length, 1'000'000); // Note: Don't scan all at once because the DB might be very big
    ustore_length_t* found_counts = nullptr;
    ustore_key_t* found_keys = nullptr;

    ustore_length_t* offsets = nullptr;
    ustore_length_t* lengths = nullptr;
    ustore_byte_t* values_ = nullptr;

    // Init scan
    ustore_scan_t scan {};
    scan.db = db_;
    scan.error = status.member_ptr();
    scan.arena = arena.member_ptr();
    scan.options = options_;
    scan.tasks_count = 1;
    scan.collections = &collection_;
    scan.start_keys = &key_;
    scan.count_limits = &len;
    scan.counts = &found_counts;
    scan.keys = &found_keys;

    // Init batch read
    ustore_read_t read {};
    read.db = db_;
    read.error = status.member_ptr();
    read.arena = arena.member_ptr();
    read.options = ustore_options_t(options_ | ustore_option_dont_discard_memory_k);
    read.collections = &collection_;
    read.keys_stride = sizeof(ustore_key_t);
    read.offsets = &offsets;
    read.lengths = &lengths;
    read.values = &values_;

    ustore_length_t scanned = 0;
    ustore_length_t remaining_keys_cnt = length;
    while (remaining_keys_cnt) {
        // First scan
        ustore_scan(&scan);
        if (!status)
            return {0, operation_status_t::error_k};

        // Then read
        read.tasks_count = *found_counts;
        read.keys = found_keys;
        ustore_read(&read);
        if (!status)
            return {0, operation_status_t::error_k};

        scanned += *found_counts;
        for (size_t idx = 0; idx < *found_counts; ++idx)
            if (lengths[idx] != ustore_length_missing_k)
                memcpy(single_value.data(), values_ + offsets[idx], lengths[idx]);

        key_ += len;
        remaining_keys_cnt = remaining_keys_cnt - len;
        len = std::min(len, remaining_keys_cnt);
    }

    return {scanned, scanned > 0 ? operation_status_t::ok_k : operation_status_t::not_found_k};
}

std::string ustore_t::info() { return fmt::format("v{}, {}", UKV_VERSION, UKV_ENGINE_NAME); }

void ustore_t::flush() {

    // Note: Workaround for flush
    ukv::status_t status;
    ustore_write_t write {};
    write.db = db_;
    write.error = status.member_ptr();
    write.arena = arena.member_ptr();
    write.options = ustore_options_t(options_ | ustore_option_write_flush_k);
    write.tasks_count = 0;
    write.collections = &collection_;
    write.keys = nullptr;
    write.lengths = nullptr;
    write.values = nullptr;
    ustore_write(&write);
}

size_t ustore_t::size_on_disk() const {
    size_t files_size = ucsb::size_on_disk(main_dir_path_);
    for (auto const& db_path : storage_dir_paths_) {
        if (fs::exists(db_path))
            files_size += ucsb::size_on_disk(db_path);
    }
    return files_size;
}

std::unique_ptr<transaction_t> ustore_t::create_transaction() {
    ukv::status_t status;
    ustore_transaction_t transaction {};

    ustore_transaction_init_t txn_init {};
    txn_init.db = db_;
    txn_init.error = status.member_ptr();
    txn_init.transaction = &transaction;
    ustore_transaction_init(&txn_init);
    if (status)
        return std::make_unique<ustore_transact_t>(db_, transaction);

    return {};
}

} // namespace ucsb::ukv
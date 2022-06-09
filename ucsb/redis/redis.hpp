#pragma once

#include <string>
#include <vector>

#include <sw/redis++/redis++.h>

#include "ucsb/core/types.hpp"
#include "ucsb/core/db.hpp"
#include "ucsb/core/helper.hpp"

namespace redis {

namespace fs = ucsb::fs;

using key_t = ucsb::key_t;
using keys_spanc_t = ucsb::keys_spanc_t;
using value_span_t = ucsb::value_span_t;
using value_spanc_t = ucsb::value_spanc_t;
using values_span_t = ucsb::values_span_t;
using values_spanc_t = ucsb::values_spanc_t;
using value_lengths_spanc_t = ucsb::value_lengths_spanc_t;
using operation_status_t = ucsb::operation_status_t;
using operation_result_t = ucsb::operation_result_t;
using transaction_t = ucsb::transaction_t;

/**
 * @brief Redis wrapper for the UCSB benchmark.
 * Using redis-plus-plus client, based on hiredis.
 * https://github.com/sewenew/redis-plus-plus
 */

struct redis_t : public ucsb::db_t {
  public:
    inline redis_t() : redis_(sw::redis::Redis("tcp://127.0.0.1:6379")) {};
    inline ~redis_t() { close(); }

    void set_config(fs::path const& config_path, fs::path const& dir_path) override;
    bool open() override;
    bool close() override;
    void destroy() override;

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
    mutable sw::redis::Redis redis_;
    fs::path config_path_;
    fs::path dir_path_;
};

inline sw::redis::StringView to_string_view(std::byte const* p, size_t size_bytes) noexcept {
    return {reinterpret_cast<const char*>(p), size_bytes};
}

inline sw::redis::StringView to_string_view(key_t const& k) noexcept {
    return {reinterpret_cast<const char*>(&k), sizeof(key_t)};
}

void redis_t::set_config(fs::path const& config_path, fs::path const& dir_path) {
    config_path_ = config_path;
    dir_path_ = dir_path;
}

bool redis_t::open() {
    return true;
}

bool redis_t::close() {
    return true;
}

void redis_t::destroy() {
    bool ok = close();
    assert(ok);
}

operation_result_t redis_t::upsert(key_t key, value_spanc_t value) {
    auto status = redis_.set(to_string_view(key),
                             to_string_view(value.data(), value.size()),
                             std::chrono::milliseconds(0),
                             sw::redis::UpdateType::ALWAYS);
    return {status, status ? operation_status_t::ok_k : operation_status_t::error_k};
}

operation_result_t redis_t::update(key_t key, value_spanc_t value) {
    auto status = redis_.set(to_string_view(key),
                             to_string_view(value.data(), value.size()),
                             std::chrono::milliseconds(0),
                             sw::redis::UpdateType::EXIST);
    return {status, status ? operation_status_t::ok_k : operation_status_t::not_found_k};
}

operation_result_t redis_t::remove(key_t key) {
    auto cnt = redis_.del(to_string_view(key));
    return {cnt, cnt ? operation_status_t::ok_k : operation_status_t::not_found_k};
}

operation_result_t redis_t::read(key_t key, value_span_t value) const {
    auto val = redis_.get(to_string_view(key));
    if (!val)
        return {0, operation_status_t::not_found_k};

    memcpy(value.data(), &val, sizeof(val));
    return {1, operation_status_t::ok_k};
}

operation_result_t redis_t::batch_upsert(keys_spanc_t keys, values_spanc_t values, value_lengths_spanc_t sizes) {
    struct kv_iterator {
        using pair_t = std::pair<sw::redis::StringView, sw::redis::StringView>;
        keys_spanc_t keys_;
        values_spanc_t values_;
        value_lengths_spanc_t sizes_;
        size_t index_;
        size_t offset_;
        pair_t pair_;

        kv_iterator(
            keys_spanc_t keys, values_spanc_t values, value_lengths_spanc_t sizes, size_t index = 0, size_t offset = 0)
            : keys_(keys), values_(values), sizes_(sizes), index_(index), offset_(offset),
              pair_(std::make_pair(to_string_view(keys_[index_]),
                                   to_string_view(values_.data() + offset_, sizes_[index_]))) {}

        pair_t const& operator*() const noexcept { return pair_; }
        pair_t const* operator->() const noexcept { return &pair_; }
        bool operator==(kv_iterator const& other) const noexcept { return other.index_ == index_; }

        kv_iterator& operator++() noexcept {
            offset_ += sizes_[index_];
            index_++;
            pair_.first = to_string_view(keys_[index_]);
            pair_.second = to_string_view(values_.data() + offset_, sizes_[index_]);
            return *this;
        }
    };

    redis_.mset(kv_iterator(keys, values, sizes), kv_iterator(keys, values, sizes, keys.size(), values.size()));
    return {keys.size(), operation_status_t::ok_k};
}

operation_result_t redis_t::batch_read(keys_spanc_t keys, values_span_t values) const {
    struct key_iterator {
        keys_spanc_t keys_;
        size_t index_;

        key_iterator(keys_spanc_t keys, size_t index = 0) : keys_(keys), index_(index) {}

        sw::redis::StringView operator*() const noexcept { return to_string_view(keys_[index_]); }
        bool operator==(key_iterator const& other) const noexcept { return index_ == other.index_; }

        key_iterator& operator++() noexcept {
            index_++;
            return *this;
        }
    };

    std::vector<sw::redis::Optional<std::string>> output;
    redis_.mget(key_iterator(keys), key_iterator(keys, keys.size()), std::back_inserter(output));

    size_t offset = 0;
    size_t cnt = 0;
    for (const auto& val : output) {
        if (!val)
            continue;
        memcpy(values.data() + offset, &val, sizeof(val));
        offset += sizeof(val);
        cnt++;
    }
    return {cnt, operation_status_t::ok_k};
}

operation_result_t redis_t::bulk_load(keys_spanc_t keys, values_spanc_t values, value_lengths_spanc_t sizes) {
    auto data_offset = 0;
    auto pipe = redis_.pipeline(false);
    for (size_t i = 0; i != keys.size(); i++) {
        pipe.set(to_string_view(keys[i]),
                 to_string_view(values.data() + data_offset, sizes[i]),
                 std::chrono::milliseconds(0),
                 sw::redis::UpdateType::ALWAYS);
        data_offset += sizes[i];
    }

    auto pipe_replies = pipe.exec();

    size_t cnt = 0;
    for (size_t i = 0; i != keys.size(); i++)
        cnt += pipe_replies.get<bool>(i);

    return {cnt, operation_status_t::ok_k};
}

operation_result_t redis_t::range_select(key_t key, size_t length, values_span_t values) const {
    return {0, operation_status_t::not_implemented_k};
}

operation_result_t redis_t::scan(key_t key, size_t length, value_span_t single_value) const {
    // auto cursor = 0LL;
    // std::unordered_set<std::string> keys;
    // cursor = redis_.scan(cursor, "*", length, std::inserter(keys, keys.begin()));
    // return {keys.size(), keys.size() ? operation_status_t::ok_k : operation_status_t::error_k};
    return {0, operation_status_t::not_implemented_k};
}

void redis_t::flush() {
}

size_t redis_t::size_on_disk() const {
    return ucsb::size_on_disk(dir_path_);
}

std::unique_ptr<transaction_t> redis_t::create_transaction() {
    return {};
}

} // namespace redis

#pragma once

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <filesystem>
#include <iomanip>
#include <span>
#include <sstream>
#include <string>
#include <vector>

#include "src/core/db.hpp"
#include "src/core/helper.hpp"
#include "src/core/types.hpp"

namespace ucsb::filekv
{

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
    using db_hints_t = ucsb::db_hints_t;
    using transaction_t = ucsb::transaction_t;

    struct fd_lock_t
    {
        int fd{-1};
        bool write_lock{false};
        fd_lock_t(int fd_, bool exclusive) : fd(fd_), write_lock(exclusive)
        {
            int how = exclusive ? LOCK_EX : LOCK_SH;
            flock(fd, how);
        }
        ~fd_lock_t()
        {
            if (fd != -1)
            {
                flock(fd, LOCK_UN);
                close(fd);
            }
        }
    };

    inline fs::path make_path(const fs::path& dir, key_t key)
    {
        std::ostringstream ss;
        ss << std::setw(10) << std::setfill('0') << key;
        std::string k = ss.str();
        return dir / k.substr(0, 4) / k.substr(4, 3) / k.substr(7, 3);
    }

    class filekv_t : public ucsb::db_t
    {
    public:
        filekv_t() = default;
        ~filekv_t() override = default;

        void set_config(fs::path const& config_path, fs::path const& main_dir_path,
                        std::vector<fs::path> const& storage_dir_paths, db_hints_t const& hints) override;

        bool open(std::string& error) override;
        std::string info() override { return "File-per-key KV"; }
        void close() override {}
        void flush() override {}
        size_t size_on_disk() const override;
        std::unique_ptr<transaction_t> create_transaction() override { return {}; }

        operation_result_t upsert(key_t key, value_spanc_t value) override;
        operation_result_t update(key_t key, value_spanc_t value) override;
        operation_result_t remove(key_t key) override;
        operation_result_t read(key_t key, value_span_t dst) const override;

        operation_result_t batch_upsert(keys_spanc_t keys, values_spanc_t values, value_lengths_spanc_t sizes) override;
        operation_result_t batch_read(keys_spanc_t keys, values_span_t dst) const override;

        operation_result_t bulk_load(keys_spanc_t keys, values_spanc_t values, value_lengths_spanc_t sizes) override
        {
            return batch_upsert(keys, values, sizes);
        }
        operation_result_t range_select(key_t, size_t, values_span_t) const override
        {
            return {0, operation_status_t::not_implemented_k};
        }
        operation_result_t scan(key_t, size_t, value_span_t) const override
        {
            return {0, operation_status_t::not_implemented_k};
        }

    private:
        fs::path data_dir_;
    };

    inline void filekv_t::set_config(fs::path const& config_path, fs::path const& main_dir_path,
                                     std::vector<fs::path> const& storage_dir_paths, db_hints_t const& hints)
    {
        data_dir_ = main_dir_path / "kv_data";
    }

    inline bool filekv_t::open(std::string& error)
    {
        std::error_code ec;
        if (!fs::exists(data_dir_))
            fs::create_directories(data_dir_, ec);
        if (ec)
        {
            error = ec.message();
            return false;
        }
        return true;
    }

    inline operation_result_t filekv_t::upsert(key_t key, value_spanc_t val)
    {
        fs::path path = make_path(data_dir_, key);

        std::error_code ec;
        fs::create_directories(path.parent_path(), ec);
        if (ec)
            return {0, operation_status_t::error_k};

        int fd = ::open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd == -1)
            return {0, operation_status_t::error_k};
        fd_lock_t lock(fd, /*exclusive*/ true);
        ssize_t written = ::write(fd, val.data(), val.size());
        return {size_t(written == static_cast<ssize_t>(val.size())),
                written == static_cast<ssize_t>(val.size()) ? operation_status_t::ok_k : operation_status_t::error_k};
    }

    inline operation_result_t filekv_t::update(key_t key, value_spanc_t val)
    {
        fs::path path = make_path(data_dir_, key);
        if (!fs::exists(path))
            return {0, operation_status_t::not_found_k};
        return upsert(key, val);
    }

    inline operation_result_t filekv_t::remove(key_t key)
    {
        fs::path path = make_path(data_dir_, key);
        if (!fs::exists(path))
            return {0, operation_status_t::not_found_k};
        std::error_code ec;
        fs::remove(path, ec);
        return {ec ? size_t(0) : size_t(1), ec ? operation_status_t::error_k : operation_status_t::ok_k};
    }

    inline operation_result_t filekv_t::read(key_t key, value_span_t dst) const
    {
        fs::path path = make_path(data_dir_, key);
        int fd = ::open(path.c_str(), O_RDONLY);
        if (fd == -1)
            return {0, operation_status_t::not_found_k};
        fd_lock_t lock(fd, /*exclusive*/ false);
        ssize_t n = ::read(fd, dst.data(), dst.size());
        return {n > 0 ? size_t(1) : size_t(0), n > 0 ? operation_status_t::ok_k : operation_status_t::error_k};
    }

    inline operation_result_t filekv_t::batch_upsert(keys_spanc_t keys, values_spanc_t vals,
                                                     value_lengths_spanc_t sizes)
    {
        size_t offset = 0;
        size_t ok = 0;
        for (size_t i = 0; i < keys.size(); ++i)
        {
            auto val_span = vals.subspan(offset, sizes[i]);
            auto res = upsert(keys[i], val_span);
            if (res.entries_touched)
                ++ok;
            offset += sizes[i];
        }
        return {ok, ok == keys.size() ? operation_status_t::ok_k : operation_status_t::error_k};
    }

    inline operation_result_t filekv_t::batch_read(keys_spanc_t keys, values_span_t dst) const
    {
        size_t offset = 0;
        size_t ok = 0;
        for (auto key : keys)
        {
            fs::path path = make_path(data_dir_, key);
            int fd = ::open(path.c_str(), O_RDONLY);
            if (fd == -1)
                break;
            fd_lock_t lock(fd, false);
            auto sz = fs::file_size(path);
            ssize_t n = ::read(fd, dst.data() + offset, sz);
            if (n == static_cast<ssize_t>(sz))
                ++ok;
            else
                break;
            offset += sz;
        }
        return {ok, ok == keys.size() ? operation_status_t::ok_k : operation_status_t::error_k};
    }

    inline size_t filekv_t::size_on_disk() const
    {
        return ucsb::size_on_disk(data_dir_);
    }

} // namespace ucsb::filekv

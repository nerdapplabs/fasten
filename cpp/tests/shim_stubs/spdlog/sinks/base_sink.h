#pragma once
// Minimal spdlog stub — provides only the surface fasten/shim/spdlog.hpp uses.
#include <mutex>
#include <string>

namespace spdlog {

namespace level {
enum level_enum {
    trace    = 0,
    debug    = 1,
    info     = 2,
    warn     = 3,
    err      = 4,
    critical = 5,
    off      = 6,
};
}

namespace details {
struct null_mutex {
    void lock()   {}
    void unlock() {}
};

struct string_view_t {
    const char* data_ = "";
    size_t      size_ = 0;
    string_view_t() = default;
    string_view_t(const std::string& s) : data_(s.data()), size_(s.size()) {}
    bool empty() const { return size_ == 0; }
    std::string to_string() const { return std::string(data_, size_); }
    auto begin() const { return data_; }
    auto end()   const { return data_ + size_; }
};

struct log_msg {
    string_view_t  logger_name;
    level::level_enum level   = level::info;
    string_view_t  payload;
};
} // namespace details

namespace sinks {
template<typename Mutex>
class base_sink {
    Mutex mutex_;
public:
    virtual ~base_sink() = default;
    void log(const details::log_msg& msg) {
        std::lock_guard<Mutex> lk(mutex_);
        sink_it_(msg);
    }
    void flush() {
        std::lock_guard<Mutex> lk(mutex_);
        flush_();
    }
protected:
    virtual void sink_it_(const details::log_msg& msg) = 0;
    virtual void flush_() = 0;
};
} // namespace sinks
} // namespace spdlog

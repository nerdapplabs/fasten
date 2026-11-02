#pragma once
/**
 * fasten/shim/spdlog.hpp: copy spdlog messages into fasten's sys log.
 *
 * Add the sink to a logger and each message is also redacted and pushed
 * to the buffer behind query_syslog() and /logs/sys.
 *
 * Usage:
 *   #include "fasten.hpp"
 *   #include "fasten/shim/spdlog.hpp"
 *   #include <spdlog/spdlog.h>
 *
 *   // After fasten::init():
 *   spdlog::default_logger()->sinks().push_back(
 *       std::make_shared<fasten::shim::spdlog_sink_mt>()
 *   );
 *
 *   // Also lands in fasten's sys log:
 *   spdlog::info("user_login user_id={}", uid);
 *
 * spdlog_sink_mt locks a mutex; spdlog_sink_st is for single-threaded use.
 * A per-thread flag stops the sink from re-entering itself.
 *
 * Requires spdlog 1.x.
 */

#include <mutex>
#include <string>
#include "fasten.hpp"
#include <spdlog/sinks/base_sink.h>

namespace fasten::shim {

namespace detail_ {
static thread_local bool spdlog_sink_active = false;
}

template <typename Mutex>
class spdlog_sink : public spdlog::sinks::base_sink<Mutex> {
protected:
    void sink_it_(const spdlog::details::log_msg& msg) override {
        if (detail_::spdlog_sink_active) return;  // recursion guard
        detail_::spdlog_sink_active = true;

        std::string level_str;
        switch (msg.level) {
            case spdlog::level::debug:   level_str = "debug";    break;
            case spdlog::level::info:    level_str = "info";     break;
            case spdlog::level::warn:    level_str = "warn";     break;
            case spdlog::level::err:     level_str = "error";    break;
            case spdlog::level::critical:level_str = "critical"; break;
            default:                     level_str = "debug";    break;
        }

        std::string event(msg.payload.begin(), msg.payload.end());
        std::string logger_name = msg.logger_name.empty()
            ? "spdlog"
            : std::string(msg.logger_name.begin(), msg.logger_name.end());

        fasten::Fields row;
        row["event"]      = fasten::detail_::redact(fasten::Fields{{"event", event}})["event"];
        row["level"]      = level_str;
        row["logger"]     = logger_name;
        row["request_id"] = fasten::detail_::tl_request_id();

        fasten::detail_::globals().syslog_ring.push(row);

        detail_::spdlog_sink_active = false;
    }

    void flush_() override {}
};

using spdlog_sink_mt = spdlog_sink<std::mutex>;
using spdlog_sink_st = spdlog_sink<spdlog::details::null_mutex>;

}  // namespace fasten::shim

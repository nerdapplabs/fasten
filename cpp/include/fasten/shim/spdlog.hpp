#pragma once
/**
 * fasten/shim/spdlog.hpp — spdlog → fasten syslog bridge.
 *
 * Header-only, opt-in. Add one sink to your spdlog logger and every
 * log line is mirrored into fasten's /logs/sys ring without changing
 * any existing call sites.
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
 *   // Existing code unchanged — now also writes to fasten ring:
 *   spdlog::info("user_login user_id={}", uid);
 *
 * Thread safety: spdlog_sink_mt is the multi-threaded variant (mutex
 * internally). spdlog_sink_st exists for single-threaded use.
 *
 * Recursion guard: the sink checks a per-thread flag before pushing
 * so fasten's own internal sys writes (via fasten::log::*) never
 * re-enter this sink even if someone accidentally adds it to the logger
 * that fasten itself uses.
 *
 * Requires: spdlog >= 1.x (sink interface stable across 1.x and 2.x).
 * Include spdlog/sinks/base_sink.h before this header.
 */

#include <mutex>
#include <string>
#include "fasten.hpp"
#include <spdlog/sinks/base_sink.h>

namespace fasten::shim {

namespace detail_ {
// static gives internal linkage per TU — correct for a header-only recursion
// guard where the sink and its callers live in the same translation unit.
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

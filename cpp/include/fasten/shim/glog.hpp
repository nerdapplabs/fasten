#pragma once
/**
 * fasten/shim/glog.hpp — glog (google/glog) → fasten syslog bridge.
 *
 * Header-only, opt-in. Call fasten::shim::glog::install() once after
 * fasten::init() and every LOG(INFO/WARNING/ERROR/FATAL) also writes
 * a syslog row into fasten's /logs/sys ring.
 *
 * Usage:
 *   #include "fasten.hpp"
 *   #include "fasten/shim/glog.hpp"
 *   #include <glog/logging.h>
 *
 *   google::InitGoogleLogging(argv[0]);
 *   fasten::init(...);
 *   fasten::shim::glog::install();
 *
 *   // Existing LOG calls unchanged:
 *   LOG(INFO) << "user_login user_id=" << uid;
 *
 * install() is idempotent — calling it multiple times registers only
 * one sink.
 *
 * Recursion guard: a per-thread flag prevents fasten's own internal
 * log writes from re-entering the glog sink.
 *
 * Requires: google/glog (any version with AddLogSink / LogSink).
 */

#include <string>
#include "fasten.hpp"
#include <glog/logging.h>

namespace fasten::shim::glog {

namespace detail_ {
static thread_local bool sink_active = false;
}

class FastenLogSink : public google::LogSink {
public:
    void send(google::LogSeverity severity,
              const char* /*full_filename*/,
              const char* base_filename,
              int /*line*/,
              const struct ::tm* /*tm_time*/,
              const char* message,
              size_t message_len) override
    {
        if (detail_::sink_active) return;
        detail_::sink_active = true;

        std::string level_str;
        switch (severity) {
            case google::GLOG_INFO:    level_str = "info";  break;
            case google::GLOG_WARNING: level_str = "warn";  break;
            case google::GLOG_ERROR:   level_str = "error"; break;
            case google::GLOG_FATAL:   level_str = "error"; break;
            default:                   level_str = "info";  break;
        }

        std::string event(message, message_len);
        std::string logger_name = base_filename ? std::string(base_filename) : "glog";

        fasten::Fields row;
        row["event"]      = fasten::detail_::redact(fasten::Fields{{"event", event}})["event"];
        row["level"]      = level_str;
        row["logger"]     = logger_name;
        row["request_id"] = fasten::detail_::tl_request_id();

        fasten::detail_::globals().syslog_ring.push(row);

        detail_::sink_active = false;
    }

    void WaitTillSent() override {}
};

/**
 * Register the fasten glog sink once. Safe to call multiple times.
 * Returns a raw pointer to the installed sink (owned by glog's registry).
 */
inline FastenLogSink* install() {
    static FastenLogSink* sink = nullptr;
    if (!sink) {
        sink = new FastenLogSink();
        google::AddLogSink(sink);
    }
    return sink;
}

/**
 * Remove the fasten glog sink (e.g. in tests or graceful shutdown).
 * No-op if install() was never called.
 */
inline void uninstall() {
    // glog does not provide a way to remove a specific sink by pointer
    // through the public API, so we rely on RemoveLogSink which was
    // added in recent versions. Guard with a feature test.
#if defined(HAVE_GLOG_REMOVE_LOG_SINK) || GLOG_VERSION_MAJOR >= 1
    static FastenLogSink* sink = nullptr;
    if (sink) {
        google::RemoveLogSink(sink);
        sink = nullptr;
    }
#endif
}

}  // namespace fasten::shim::glog

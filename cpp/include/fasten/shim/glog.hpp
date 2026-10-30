#pragma once
/**
 * fasten/shim/glog.hpp: copy glog messages into fasten's sys log.
 *
 * After fasten::shim::glog::install(), each LOG(...) message is also
 * redacted and pushed to the buffer behind query_syslog() and /logs/sys.
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
 *   // Also lands in fasten's sys log:
 *   LOG(INFO) << "user_login user_id=" << uid;
 *
 * install() registers the sink only once. A per-thread flag stops the
 * sink from re-entering itself.
 *
 * Requires glog with LogSink and AddLogSink.
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

// Register the sink on the first call; later calls return the same sink.
// The sink is never freed.
inline FastenLogSink* install() {
    static FastenLogSink* sink = nullptr;
    if (!sink) {
        sink = new FastenLogSink();
        google::AddLogSink(sink);
    }
    return sink;
}

// Does nothing at present: `sink` here is a separate static from the one
// in install(), so it is always null and RemoveLogSink is never called.
inline void uninstall() {
#if defined(HAVE_GLOG_REMOVE_LOG_SINK) || GLOG_VERSION_MAJOR >= 1
    static FastenLogSink* sink = nullptr;
    if (sink) {
        google::RemoveLogSink(sink);
        sink = nullptr;
    }
#endif
}

}  // namespace fasten::shim::glog

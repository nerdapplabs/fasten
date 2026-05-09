#pragma once
/**
 * fasten/shim/boost_log.hpp — Boost.Log → fasten syslog bridge.
 *
 * Header-only, opt-in. Add the fasten backend to your Boost.Log core
 * and every log record is mirrored into fasten's /logs/sys ring.
 *
 * Usage:
 *   #include "fasten.hpp"
 *   #include "fasten/shim/boost_log.hpp"
 *   #include <boost/log/core.hpp>
 *
 *   namespace logging = boost::log;
 *   logging::core::get()->add_sink(
 *       std::make_shared<fasten::shim::boost_log::sink_mt>()
 *   );
 *
 *   // Existing BOOST_LOG_TRIVIAL calls unchanged:
 *   BOOST_LOG_TRIVIAL(info) << "user_login user_id=" << uid;
 *
 * Thread safety: sink_mt is multi-threaded (uses a mutex). sink_st is
 * single-threaded for environments where locking is not needed.
 *
 * Recursion guard: a per-thread flag prevents fasten's own internal
 * log writes from re-entering this sink.
 *
 * Requires: Boost.Log (boost >= 1.54). Link with
 *   boost_log boost_log_setup boost_thread boost_system.
 */

#include <string>
#include <mutex>
#include "fasten.hpp"
#include <boost/log/core/record_view.hpp>
#include <boost/log/sinks/sync_frontend.hpp>
#include <boost/log/sinks/async_frontend.hpp>
#include <boost/log/sinks/basic_sink_backend.hpp>
#include <boost/log/attributes/value_visitation.hpp>
#include <boost/log/trivial.hpp>

namespace fasten::shim::boost_log {

namespace detail_ {
static thread_local bool sink_active = false;
}

/**
 * Backend that pushes records into the fasten syslog ring.
 * frontend (sync_frontend / async_frontend) wraps this backend and
 * provides the thread-safety model.
 */
class fasten_backend :
    public boost::log::sinks::basic_formatted_sink_backend<
        char,
        boost::log::sinks::synchronized_feeding
    >
{
public:
    void consume(boost::log::record_view const& rec,
                 string_type const& formatted_message)
    {
        if (detail_::sink_active) return;
        detail_::sink_active = true;

        std::string level_str = "info";
        auto sev_attr = rec[boost::log::trivial::severity];
        if (sev_attr) {
            switch (sev_attr.get()) {
                case boost::log::trivial::debug:   level_str = "debug";    break;
                case boost::log::trivial::info:    level_str = "info";     break;
                case boost::log::trivial::warning: level_str = "warn";     break;
                case boost::log::trivial::error:   level_str = "error";    break;
                case boost::log::trivial::fatal:   level_str = "error";    break;
                default: break;
            }
        }

        fasten::Fields row;
        row["event"]  = fasten::detail_::redact(
            fasten::Fields{{"event", formatted_message}})["event"];
        row["level"]      = level_str;
        row["logger"]     = "boost_log";
        row["request_id"] = fasten::detail_::tl_request_id();

        fasten::detail_::globals().syslog_ring.push(row);

        detail_::sink_active = false;
    }
};

// Convenience type aliases matching the spdlog naming convention.
using sink_mt = boost::log::sinks::synchronous_sink<fasten_backend>;

}  // namespace fasten::shim::boost_log

#pragma once
/**
 * fasten/shim/boost_log.hpp: copy Boost.Log records into fasten's sys log.
 *
 * Add sink_mt to the Boost.Log core and each record is also redacted and
 * pushed to the buffer behind query_syslog() and /logs/sys.
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
 *   // Also lands in fasten's sys log:
 *   BOOST_LOG_TRIVIAL(info) << "user_login user_id=" << uid;
 *
 * A per-thread flag stops the sink from re-entering itself.
 *
 * Requires Boost.Log 1.54+. Link boost_log, boost_log_setup, boost_thread
 * and boost_system.
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

// Pushes each record to the sys log buffer. The frontend that wraps it
// decides the threading model.
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

// Synchronous frontend around fasten_backend.
using sink_mt = boost::log::sinks::synchronous_sink<fasten_backend>;

}  // namespace fasten::shim::boost_log

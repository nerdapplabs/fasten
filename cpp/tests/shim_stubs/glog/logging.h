#pragma once
// Minimal glog stub — provides only the surface fasten/shim/glog.hpp uses.
#include <ctime>
#include <string>

namespace google {

enum LogSeverity {
    GLOG_INFO    = 0,
    GLOG_WARNING = 1,
    GLOG_ERROR   = 2,
    GLOG_FATAL   = 3,
};

class LogSink {
public:
    virtual ~LogSink() = default;
    virtual void send(LogSeverity severity,
                      const char* full_filename,
                      const char* base_filename,
                      int         line,
                      const struct ::tm* tm_time,
                      const char* message,
                      size_t      message_len) = 0;
    virtual void WaitTillSent() = 0;
};

// No-op in tests — shim smoke tests call send() directly.
inline void AddLogSink(LogSink*) {}
inline void RemoveLogSink(LogSink*) {}

// Version guard used by the uninstall() helper.
#define GLOG_VERSION_MAJOR 1

} // namespace google

// Host-test stub for <android-base/logging.h>: LOG()/PLOG() to stderr (and $AOHP_LOG_FILE if set).
#pragma once
#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <mutex>
#include <sstream>
#include <string>

namespace android { namespace base {
enum LogSeverity { VERBOSE, DEBUG, INFO, WARNING, ERROR, FATAL_WITHOUT_ABORT, FATAL };
enum LogId { MAIN, SYSTEM };
struct LogdLogger { explicit LogdLogger(LogId = MAIN) {} };
inline void InitLogging(char**, LogdLogger = LogdLogger()) {}
inline void StderrLogger(LogId, int, const char*, const char*, unsigned int, const char*) {}
template <typename F> inline void InitLogging(char**, F) {}

class LogMessage {
public:
    LogMessage(const char* file, int line, LogSeverity sev, bool withErrno)
        : sev_(sev), err_(withErrno ? errno : 0) { (void)file; (void)line; }
    ~LogMessage() {
        static std::mutex mu;
        static const char* names[] = {"V", "D", "I", "W", "E", "F", "F"};
        std::string msg = ss_.str();
        if (err_) msg += std::string(": ") + strerror(err_);
        std::lock_guard<std::mutex> lk(mu);
        std::string line = std::string("[aohp-containerd ") + names[sev_] + "] " + msg + "\n";
        std::cerr << line;
        const char* f = getenv("AOHP_LOG_FILE");
        if (f) { std::ofstream o(f, std::ios::app); o << line; }
        if (sev_ == FATAL) abort();
    }
    std::ostream& stream() { return ss_; }
private:
    LogSeverity sev_;
    int err_;
    std::ostringstream ss_;
};
}}  // namespace android::base

#define LOG(sev) ::android::base::LogMessage(__FILE__, __LINE__, ::android::base::sev, false).stream()
#define PLOG(sev) ::android::base::LogMessage(__FILE__, __LINE__, ::android::base::sev, true).stream()

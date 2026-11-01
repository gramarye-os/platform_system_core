/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#define LOG_TAG "aohp-containerd"

#include "cgroup_controller.h"

#include <cerrno>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <sstream>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/strings.h>

namespace aohp {

namespace {

constexpr const char* kDefaultCgroupRoot = "/sys/fs/cgroup";
constexpr const char* kDefaultMemoryMax = "8589934592";   // 8 GiB
constexpr const char* kDefaultMemorySwapMax = "0";
constexpr const char* kDefaultCpuMax = "max 100000";
constexpr const char* kDefaultPidsMax = "8192";

bool mkdirParents(const std::string& path, mode_t mode) {
    if (path.empty() || path[0] != '/') return false;
    size_t pos = 0;
    while ((pos = path.find('/', pos + 1)) != std::string::npos) {
        std::string partial = path.substr(0, pos);
        if (partial.empty()) continue;
        if (mkdir(partial.c_str(), mode) != 0 && errno != EEXIST) {
            return false;
        }
    }
    return true;
}

uint64_t parseHumanSize(const std::string& s) {
    std::string t = android::base::Trim(s);
    if (t.empty()) return 0;
    char* end = nullptr;
    double v = strtod(t.c_str(), &end);
    if (end == t.c_str()) return 0;
    while (*end == ' ' || *end == '\t') ++end;
    std::string suf(end);
    uint64_t mul = 1;
    if (suf.empty() || suf == "B" || suf == "b") {
        mul = 1;
    } else if (suf == "K" || suf == "k" || android::base::StartsWith(suf, "Ki")) {
        mul = 1024ULL;
    } else if (suf == "M" || suf == "m" || android::base::StartsWith(suf, "Mi")) {
        mul = 1024ULL * 1024;
    } else if (suf == "G" || suf == "g" || android::base::StartsWith(suf, "Gi")) {
        mul = 1024ULL * 1024 * 1024;
    }
    return static_cast<uint64_t>(v * static_cast<double>(mul));
}

}  // namespace

CgroupController::CgroupController() {
    mCgroupRoot_ = kDefaultCgroupRoot;
    mMemoryMax = kDefaultMemoryMax;
    mMemorySwapMax = kDefaultMemorySwapMax;
    mCpuMax = kDefaultCpuMax;
    mPidsMax = kDefaultPidsMax;
}

void CgroupController::loadConfig(const char* path) {
    mV2Detected_ = false;
    mEnabled_ = false;
    struct stat st;
    if (stat((mCgroupRoot_ + "/cgroup.controllers").c_str(), &st) != 0) {
        LOG(WARNING) << "cgroup v2 not detected at " << mCgroupRoot_;
        return;
    }
    mV2Detected_ = true;

    std::ifstream in(path);
    if (in) {
        std::string line;
        while (std::getline(in, line)) {
            line = android::base::Trim(line);
            if (line.empty() || line[0] == '#') continue;
            size_t eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string key = android::base::Trim(line.substr(0, eq));
            std::string val = android::base::Trim(line.substr(eq + 1));
            if (key == "memory.max") {
                std::string bytes;
                if (parseSizeToString(val, &bytes)) mMemoryMax = bytes;
                else mMemoryMax = val;
            } else if (key == "memory.swap.max") {
                std::string bytes;
                if (parseSizeToString(val, &bytes)) mMemorySwapMax = bytes;
                else mMemorySwapMax = val;
            } else if (key == "cpu.max") {
                mCpuMax = val;
            } else if (key == "pids.max") {
                mPidsMax = val;
            }
        }
    } else {
        LOG(INFO) << "cgroup config missing, using defaults: " << path;
    }

    mEnabled_ = true;
    LOG(INFO) << "cgroup v2 enabled memory.max=" << mMemoryMax << " cpu.max=" << mCpuMax;
}

bool CgroupController::parseSizeToString(const std::string& in, std::string* outBytes) {
    std::string t = android::base::Trim(in);
    if (t == "max") {
        *outBytes = "max";
        return true;
    }
    uint64_t n = parseHumanSize(t);
    if (n == 0 && t != "0") return false;
    *outBytes = std::to_string(n);
    return true;
}

std::string CgroupController::sanitizeName(const std::string& name) {
    std::string out;
    out.reserve(name.size());
    for (char c : name) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
            c == '-' || c == '_') {
            out += c;
        } else {
            out += '_';
        }
    }
    if (out.empty()) out = "env";
    return "aohp-" + out;
}

std::string CgroupController::cgroupPathFor(const std::string& containerName) const {
    return mCgroupRoot_ + "/" + sanitizeName(containerName);
}

bool CgroupController::writeFile(const std::string& path, const std::string& value) {
    int fd = open(path.c_str(), O_WRONLY);
    if (fd < 0) {
        PLOG(WARNING) << "open " << path;
        return false;
    }
    bool ok = write(fd, value.data(), value.size()) == static_cast<ssize_t>(value.size());
    close(fd);
    return ok;
}

std::string CgroupController::readFileTrim(const std::string& path) {
    std::ifstream in(path.c_str());
    if (!in) return "";
    std::ostringstream oss;
    oss << in.rdbuf();
    return android::base::Trim(oss.str());
}

bool CgroupController::createForContainer(const std::string& containerName) {
    if (!mEnabled_ || !mV2Detected_) return false;
    std::string cg = cgroupPathFor(containerName);
    if (!mkdirParents(cg, 0755)) {
        PLOG(ERROR) << "mkdirParents " << cg;
        return false;
    }
    if (mkdir(cg.c_str(), 0755) != 0 && errno != EEXIST) {
        PLOG(ERROR) << "mkdir " << cg;
        return false;
    }
    std::string err;
    if (!writeFile(cg + "/memory.max", mMemoryMax + "\n")) err += "memory.max;";
    if (!writeFile(cg + "/memory.swap.max", mMemorySwapMax + "\n")) err += "memory.swap.max;";
    if (!writeFile(cg + "/cpu.max", mCpuMax + "\n")) err += "cpu.max;";
    if (!writeFile(cg + "/pids.max", mPidsMax + "\n")) err += "pids.max;";
    if (!err.empty()) {
        LOG(ERROR) << "cgroup write partial fail: " << err;
        return false;
    }
    return true;
}

void CgroupController::destroyForContainer(const std::string& containerName) {
    if (!mEnabled_) return;
    std::string cg = cgroupPathFor(containerName);
    if (rmdir(cg.c_str()) != 0 && errno != ENOENT) {
        PLOG(WARNING) << "rmdir cgroup " << cg;
    }
}

bool CgroupController::joinContainerCgroup(const std::string& containerName, pid_t pid) {
    if (!mEnabled_ || !mV2Detected_) return true;  // no-op
    std::string cg = cgroupPathFor(containerName);
    struct stat st;
    if (stat(cg.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        // createForContainer failed or cgroup not present — run without per-env limits.
        return true;
    }
    std::string path = cg + "/cgroup.procs";
    std::string s = std::to_string(static_cast<int>(pid)) + "\n";
    if (!writeFile(path, s)) {
        // Common on devices where root cgroup did not delegate +cpu/+pids to children.
        PLOG(WARNING) << "join cgroup failed " << path;
    }
    return true;
}

static constexpr const char* kPowerModeFile = "/data/aohp/power";

bool CgroupController::parsePowerMode(const std::string& s, PowerMode* out) {
    if (s == "performance" || s == "perf") { *out = PowerMode::kPerformance; return true; }
    if (s == "saver" || s == "background") { *out = PowerMode::kSaver; return true; }
    return false;
}

void CgroupController::loadPowerMode() {
    PowerMode m;
    if (parsePowerMode(readFileTrim(kPowerModeFile), &m)) mPowerMode_ = m;
    LOG(INFO) << "power mode " << powerModeName(mPowerMode_);
}

bool CgroupController::setPowerMode(PowerMode m) {
    mPowerMode_ = m;
    // writeFile() is O_WRONLY for cgroup knobs; the mode file has to be created.
    int fd = open(kPowerModeFile, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        PLOG(WARNING) << "persist power mode " << kPowerModeFile;
    } else {
        std::string s = std::string(powerModeName(m)) + "\n";
        if (write(fd, s.data(), s.size()) != static_cast<ssize_t>(s.size())) PLOG(WARNING) << "write " << kPowerModeFile;
        close(fd);
    }
    LOG(INFO) << "power mode -> " << powerModeName(m);
    return true;
}

void CgroupController::joinCpuset(pid_t pid) const {
    const char* tasks = cpusetFor(mPowerMode_);
    if (access(tasks, W_OK) != 0) return;  // no Android cpuset hierarchy (Cuttlefish without it): inherit
    if (!writeFile(tasks, std::to_string(static_cast<int>(pid)) + "\n")) {
        PLOG(WARNING) << "cpuset join failed " << tasks << " pid " << pid;
    }
}

void CgroupController::applyCpusetToContainer(const std::string& containerName) const {
    if (!mEnabled_ || !mV2Detected_) return;
    applyCpusetToProcs(cgroupPathFor(containerName) + "/cgroup.procs", containerName);
}

// Every process the daemon ever spawned - containers, exec sessions, units, HostExec helpers and their
// orphaned grandchildren - stays in the cgroup v2 group init/libprocessgroup created for the daemon
// service itself (/proc/self/cgroup "0::/system/uid_0/pid_N"), whether or not the per-env cgroups are
// usable on this device (they are not on dodge: the root does not delegate). That group is the reliable
// enumeration for a power-mode switch.
void CgroupController::applyCpusetToAll() const {
    std::ifstream self("/proc/self/cgroup");
    std::string line, path;
    while (std::getline(self, line)) {
        if (line.rfind("0::", 0) == 0) { path = line.substr(3); break; }
    }
    if (path.empty()) { LOG(WARNING) << "no cgroup v2 path for self"; return; }
    applyCpusetToProcs("/sys/fs/cgroup" + path + "/cgroup.procs", "daemon group " + path);
}

void CgroupController::applyCpusetToProcs(const std::string& procsFile, const std::string& what) const {
    std::ifstream in(procsFile);
    std::string line;
    int moved = 0;
    pid_t self = getpid();
    while (std::getline(in, line)) {
        if (line.empty()) continue;
        pid_t pid = static_cast<pid_t>(std::stoi(line));
        if (pid == self) continue;  // the daemon stays in system-background
        joinCpuset(pid);
        moved++;
    }
    LOG(INFO) << "cpuset " << powerModeName(mPowerMode_) << " applied to " << moved << " processes (" << what << ")";
}

std::string CgroupController::getUsageJson(const std::string& containerName) const {
    std::string cg = cgroupPathFor(containerName);
    struct stat st;
    if (stat(cg.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) {
        return "{\"cgroupEnabled\":false,\"cgroupPath\":\"" + cg + "\"}";
    }
    std::string memCur = readFileTrim(cg + "/memory.current");
    std::string memMax = readFileTrim(cg + "/memory.max");
    std::string memPeak = readFileTrim(cg + "/memory.peak");
    std::string pidsCur = readFileTrim(cg + "/pids.current");
    std::string cpuStat = readFileTrim(cg + "/cpu.stat");
    uint64_t cpuUsec = 0;
    if (!cpuStat.empty()) {
        std::istringstream iss(cpuStat);
        std::string line;
        while (std::getline(iss, line)) {
            if (android::base::StartsWith(line, "usage_usec ")) {
                cpuUsec = strtoull(line.c_str() + 9, nullptr, 10);
                break;
            }
        }
    }
    auto esc = [](const std::string& s) {
        std::string o;
        for (char c : s) {
            if (c == '\\' || c == '"') o += '\\';
            o += c;
        }
        return o;
    };
    return std::string("{\"cgroupEnabled\":true,\"cgroupPath\":\"") + esc(cg) +
           "\",\"memoryCurrent\":" + (memCur.empty() ? "0" : memCur) +
           ",\"memoryMax\":\"" + esc(memMax) + "\",\"memoryPeak\":" +
           (memPeak.empty() ? "0" : memPeak) + ",\"cpuUsageUsec\":" + std::to_string(cpuUsec) +
           ",\"pidsCurrent\":" + (pidsCur.empty() ? "0" : pidsCur) + "}";
}

std::string CgroupController::diagnoseJson(const std::string& containerName) const {
    std::string cg = cgroupPathFor(containerName);
    return std::string("{\"cgroupV2Detected\":") + (mV2Detected_ ? "true" : "false") +
           ",\"cgroupEnabled\":" + (mEnabled_ ? "true" : "false") + ",\"cgroupPath\":\"" +
           cg + "\",\"memoryMaxConfigured\":\"" + mMemoryMax + "\"}";
}

}  // namespace aohp

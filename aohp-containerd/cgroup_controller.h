/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#pragma once

#include <string>

#include <sys/types.h>

namespace aohp {

/** cgroup v2 resource limits for one AOHP container (env). */
class CgroupController {
public:
    CgroupController();

    /** Load limits from config (defaults if missing). Call once at startup. */
    void loadConfig(const char* path);

    bool isEnabled() const { return mEnabled_; }

    /** Create cgroup dir and write memory.max, cpu.max, pids.max, etc. */
    bool createForContainer(const std::string& containerName);

    /** Remove cgroup directory (processes must already be gone). */
    void destroyForContainer(const std::string& containerName);

    /** Best-effort: move pid into this container's cgroup before chroot (logs on failure; always ok to continue). */
    bool joinContainerCgroup(const std::string& containerName, pid_t pid);

    /** JSON: memoryCurrent, memoryMax, memoryPeak, cpuUsageUsec, pidsCurrent, cgroupPath */
    std::string getUsageJson(const std::string& containerName) const;

    std::string cgroupPathFor(const std::string& containerName) const;

    /** JSON fragment for diagnose: cgroupEnabled, cgroupPath, memoryMaxConfigured */
    std::string diagnoseJson(const std::string& containerName) const;

    /**
     * Power mode = which Android cpuset env processes run in. The daemon itself stays in
     * system-background (little cores: its own work is trivial); every process it spawns is placed
     * explicitly, because cpusets are inherited and the Pixel 6 ran the whole env on four A55s.
     *   performance (default): top-app, all cores
     *   saver: system-background, little cores only - follows Android Battery Saver by default
     * Persisted in /data/aohp/power so a daemon restart keeps it.
     */
    enum class PowerMode { kPerformance, kSaver };
    PowerMode powerMode() const { return mPowerMode_; }
    static const char* powerModeName(PowerMode m) { return m == PowerMode::kSaver ? "saver" : "performance"; }
    static bool parsePowerMode(const std::string& s, PowerMode* out);
    void loadPowerMode();
    bool setPowerMode(PowerMode m);
    /** Put pid (normally getpid() in the child before exec) into the cpuset of the current mode. */
    void joinCpuset(pid_t pid) const;
    /** Move every live process of this container's cgroup into the cpuset of the current mode. */
    void applyCpusetToContainer(const std::string& containerName) const;
    /** Move every process the daemon spawned (its own cgroup v2 group) into the cpuset of the current mode. */
    void applyCpusetToAll() const;

private:
    bool mEnabled_ = false;
    bool mV2Detected_ = false;
    std::string mCgroupRoot_;
    std::string mMemoryMax;
    std::string mMemorySwapMax;
    std::string mCpuMax;
    std::string mPidsMax;
    PowerMode mPowerMode_ = PowerMode::kPerformance;
    void applyCpusetToProcs(const std::string& procsFile, const std::string& what) const;
    static const char* cpusetFor(PowerMode m) { return m == PowerMode::kSaver ? "/dev/cpuset/system-background/tasks" : "/dev/cpuset/top-app/tasks"; }

    static std::string sanitizeName(const std::string& name);
    static bool writeFile(const std::string& path, const std::string& value);
    static std::string readFileTrim(const std::string& path);
    static bool parseSizeToString(const std::string& in, std::string* outBytes);
};

}  // namespace aohp

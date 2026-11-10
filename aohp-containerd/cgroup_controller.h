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

    /**
     * Best-effort: move pid into the env's leaf group (<env group>/init). Every process the daemon
     * puts in an env lives there; the env group itself stays process-free so controllers can be
     * enabled for the children an OCI runtime creates beside the leaf (cgroup v2 no-internal-process
     * rule). Logs on failure; always ok to continue.
     */
    bool joinContainerCgroup(const std::string& containerName, pid_t pid);

    /** <env group>/init, the leaf the env's own processes live in. */
    std::string leafPathFor(const std::string& containerName) const;

    /**
     * First entry of an env that gets its own cgroup namespace: unshare(CLONE_NEWCGROUP) makes the
     * caller's current group the namespace root, and that has to be the env group, not the leaf, so
     * the runtime's groups land beside the leaf. A process may only be written into a group whose
     * subtree_control is empty, so this prunes empty descendant groups, clears the controllers and
     * moves pid into the env group. False when a live tree (containers from before a daemon
     * restart) makes that impossible; the caller then joins the leaf without a namespace.
     */
    bool placeAtGroupRoot(const std::string& containerName, pid_t pid);

    /** Enable the delegated controllers (memory, pids, and cpu where it exists) for the env group's children. */
    void enableSubtree(const std::string& containerName);

    /** Kill every process in the env tree with cgroup.kill (5.14+). False when the knob is missing. */
    bool killAll(const std::string& containerName);

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
    void applyCpusetToTree(const std::string& dir, const std::string& what) const;
    static bool groupHasProcs(const std::string& dir);
    static void pruneEmptyChildren(const std::string& dir);
    static const char* cpusetFor(PowerMode m) { return m == PowerMode::kSaver ? "/dev/cpuset/system-background/tasks" : "/dev/cpuset/top-app/tasks"; }

    static std::string sanitizeName(const std::string& name);
    static bool writeFile(const std::string& path, const std::string& value);
    static std::string readFileTrim(const std::string& path);
    static bool parseSizeToString(const std::string& in, std::string* outBytes);
};

}  // namespace aohp

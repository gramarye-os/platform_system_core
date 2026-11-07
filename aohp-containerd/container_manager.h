/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#pragma once

#include <map>
#include <memory>
#include <mutex>
#include <string>
#include <vector>

#include "cgroup_controller.h"

namespace aohp {

class UnitManager;

/** What to run inside a container for a unit (see unit_manager.h). */
struct SpawnSpec {
    std::vector<std::string> argv;   // e.g. {"/bin/sh", "-c", cmd}
    std::vector<std::string> env;    // complete KEY=VALUE environment (replaces the daemon's)
    std::string workDir = "/";       // path inside the rootfs
    bool workDirOptional = true;     // fall back to / when missing
    std::string logPath;             // host path; stdout+stderr appended (empty = /dev/null)
    bool host = false;               // HostExec=: no mount ns / bind mounts / chroot; argv+workDir are host paths
};

struct ExecResult {
    int exitCode;
    std::string stdoutStr;
    std::string stderrStr;
};

class ContainerManager {
public:
    ContainerManager();
    ~ContainerManager();

    std::vector<std::string> listContainers();
    bool createContainer(const std::string& name, const std::string& templateName);
    bool destroyContainer(const std::string& name);
    bool resetContainer(const std::string& name);
    ExecResult execSync(const std::string& name, const std::string& command, int timeoutMs);

    int openShell(const std::string& name);

    const std::string& getLastError() const { return mLastError_; }

    /**
     * Fork one process into the container: own session + process group (pgid == pid), fresh
     * mount namespace with the standard binds, env cgroup, chroot, chdir(workDir), stdout/stderr
     * to logPath, daemon fds closed, execve(argv, env). The caller owns waitpid().
     * Returns the pid or -1 (error text in *err). No --jitless injection.
     */
    pid_t spawnInContainer(const std::string& name, const SpawnSpec& spec, std::string* err);

    UnitManager& units() { return *mUnits_; }

    std::string templateInfo(const std::string& name);

    long startService(const std::string& name, const std::string& serviceId, const std::string& command);
    bool stopService(const std::string& name, const std::string& serviceId);
    std::string listServicesJson(const std::string& name);
    std::string serviceLogTail(const std::string& name, const std::string& serviceId, int tailBytes);
    std::string getUsageJson(const std::string& name);
    std::string diagnose(const std::string& name);

    /** Remove stale .pid files when the child died externally; call at daemon startup. */
    void adoptOrphanServicePids();

    CgroupController& cgroup() { return mCgroup_; }

private:
    std::string mLastError_;
    std::mutex mWorkDirMutex_;
    std::map<std::string, std::string> mWorkDir_;

    CgroupController mCgroup_;
    std::unique_ptr<UnitManager> mUnits_;

    std::string rootfsPath(const std::string& name);
    // Name of the env whose rootfs is <pid>'s root directory (chroot), or "" when the pid is not an
    // env process. Used by the Driver's credential broker to turn a SO_PEERCRED pid into an
    // "env:<name>" principal: every env process is uid 0 in the host uid space, so the uid alone
    // cannot tell envs apart (or apart from host root).
    std::string envOfPid(pid_t pid);
    std::string envPath(const std::string& name);
    std::string templatePath(const std::string& templateName);
    std::string templateRecordPath(const std::string& name);
    std::string servicesDirPath(const std::string& name);

    bool extractTemplate(const std::string& templateTarGz, const std::string& destDir);
    bool setupBindMounts(const std::string& rootfs);
    bool teardownBindMounts(const std::string& rootfs);
    void killContainerProcesses(const std::string& rootfs);
    int forkIntoContainer(const std::string& containerName, const std::string& rootfs,
                          const char* const argv[], bool usePty);

    bool writeTemplateRecord(const std::string& name, const std::string& templateName);
    std::string readTemplateRecord(const std::string& name);
    std::string firstTemplateTarInTemplateDir();

    static bool isValidServiceId(const std::string& id);
};

}  // namespace aohp

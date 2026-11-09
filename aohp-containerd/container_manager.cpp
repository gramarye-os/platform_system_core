/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#define LOG_TAG "aohp-containerd"

#include "container_manager.h"
#include "protocol.h"
#include "tar_gz_extract.h"
#include "unit_manager.h"

#include <cerrno>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <sstream>

#include <algorithm>
#include <tuple>
#include <vector>

#include <dirent.h>
#include <mntent.h>
#include <fcntl.h>
#include <pty.h>
#include <sched.h>
#include <signal.h>
#include <sys/mount.h>
#include <sys/syscall.h>
#ifdef __BIONIC__
#include <linux/mount.h>  // struct mount_attr; glibc >= 2.36 has it in <sys/mount.h> (hosttest)
#endif
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <android-base/strings.h>

namespace aohp {

namespace {


bool mkdirParentsAbsolute(const std::string& path, mode_t mode) {
    if (path.empty() || path[0] != '/') return false;
    size_t pos = 0;
    while ((pos = path.find('/', pos + 1)) != std::string::npos) {
        std::string partial = path.substr(0, pos);
        if (partial.empty()) continue;
        if (mkdir(partial.c_str(), mode) != 0 && errno != EEXIST) {
            PLOG(ERROR) << "mkdirParentsAbsolute " << partial;
            return false;
        }
    }
    return true;
}

bool ensureDir(const std::string& path, mode_t mode) {
    if (!mkdirParentsAbsolute(path, mode)) return false;
    if (mkdir(path.c_str(), mode) != 0 && errno != EEXIST) {
        PLOG(ERROR) << "ensureDir mkdir " << path;
        return false;
    }
    struct stat sb;
    if (stat(path.c_str(), &sb) != 0 || !S_ISDIR(sb.st_mode)) {
        LOG(ERROR) << "ensureDir not a directory: " << path;
        return false;
    }
    return true;
}

void tryUnshareMountNs() {
    if (unshare(CLONE_NEWNS) != 0) {
        // Never run container setup in the host mount namespace: the bind mounts and
        // MNT_DETACH teardown below would land on the real /dev, /proc, /sys.
        PLOG(ERROR) << "unshare(CLONE_NEWNS) failed; refusing to run in host mount namespace";
        _exit(126);
    }
    // A freshly unshared mount namespace inherits MS_SHARED propagation on most mounts.
    // Without flipping the root to MS_SLAVE (same trick zygote / init's SetUpMountNamespace
    // uses), every bind mount in this child — /proc, /dev, /sys, /sdcard, and especially
    // each `newinstance` devpts — propagates back to the host namespace and survives the
    // child's exit. After ~10 execSyncs the host accumulates dozens of stale mounts plus a
    // new devpts instance each time, which bogs down the whole VM and eventually makes
    // setupBindMounts() fail for all subsequent commands.
    if (mount("rootfs", "/", nullptr, MS_SLAVE | MS_REC, nullptr) != 0) {
        // Observed on an enforcing Pixel 6 when sepolicy lacked `allow aohp_container_daemon
        // rootfs:dir mounton`: every exec leaked its binds to the host (21k mounts) and the
        // detach on teardown unmounted the host's /sys/fs/selinux, crashing Settings and the
        // AgentDriver. A leaking namespace is worse than a failed exec.
        PLOG(ERROR) << "make-rslave / failed; refusing to run with shared mount propagation";
        _exit(126);
    }
}

// Node/V8 allocates RW->RX pages for JIT by default. On some Android / hardened
// kernels those mmaps fail (V8 CHECK: errno 12 ENOMEM). --jitless avoids runtime
// executable mappings; fine for the bundled aohp CLI in AOHP containers.
void setContainerNodeOptionsJitless() {
    const char* existing = getenv("NODE_OPTIONS");
    // --jitless: avoid executable mmap failures on hardened/Android environments.
    // --no-warnings: suppress V8 noise when --jitless disables --expose_wasm (harmless).
    std::string merged = "--jitless --no-warnings";
    if (existing != nullptr && existing[0] != '\0') {
        merged = std::string(existing) + " --jitless --no-warnings";
    }
    setenv("NODE_OPTIONS", merged.c_str(), 1);
}

void setContainerChildCommonEnv() {
    setenv("HOME", "/root", 1);
    setenv("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin", 1);
    setenv("TERM", "xterm-256color", 1);
    setenv("LANG", "C.UTF-8", 1);
    // Quiets Node/V8 noise (e.g. --jitless vs default --expose_wasm) without hiding user code warnings.
    setenv("NODE_NO_WARNINGS", "1", 0);
    setContainerNodeOptionsJitless();
}

std::string jsonEscape(const std::string& s) {
    std::string o;
    o.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '\\':
                o += "\\\\";
                break;
            case '"':
                o += "\\\"";
                break;
            case '\n':
                o += "\\n";
                break;
            case '\r':
                o += "\\r";
                break;
            case '\t':
                o += "\\t";
                break;
            default:
                o += c;
                break;
        }
    }
    return o;
}

std::string extractJsonStringField(const std::string& j, const char* key) {
    std::string pat = std::string("\"") + key + "\":\"";
    size_t p = j.find(pat);
    if (p == std::string::npos) return "";
    p += pat.size();
    std::string o;
    while (p < j.size()) {
        if (j[p] == '\\' && p + 1 < j.size()) {
            o += j[p + 1];
            p += 2;
            continue;
        }
        if (j[p] == '"') break;
        o += j[p++];
    }
    return o;
}

long long extractJsonIntField(const std::string& j, const char* key) {
    std::string pat = std::string("\"") + key + "\":";
    size_t p = j.find(pat);
    if (p == std::string::npos) return 0;
    p += pat.size();
    while (p < j.size() && (j[p] == ' ' || j[p] == '\t')) ++p;
    return strtoll(j.c_str() + p, nullptr, 10);
}

}  // namespace

ContainerManager::ContainerManager() {
    mkdir(CONTAINER_BASE_DIR, 0770);
    mkdir(SHARED_BASE, 0770);
    mkdir(SHARED_NPM_CACHE, 0770);
    mkdir(SHARED_OPENCLAW_DEV, 0770);
    mkdir(SHARED_UDA, 0770);
    mCgroup_.loadConfig(AOHP_CGROUP_CONF);
    mCgroup_.loadPowerMode();
    mUnits_.reset(new UnitManager(*this));
}

ContainerManager::~ContainerManager() {}

std::string ContainerManager::envPath(const std::string& name) {
    return std::string(CONTAINER_BASE_DIR) + "/" + name;
}

std::string ContainerManager::rootfsPath(const std::string& name) {
    return envPath(name) + "/rootfs";
}

std::string ContainerManager::templatePath(const std::string& templateName) {
    return std::string(TEMPLATE_DIR) + "/" + templateName + ".tar.gz";
}

std::string ContainerManager::templateRecordPath(const std::string& name) {
    return envPath(name) + "/.template";
}

std::string ContainerManager::servicesDirPath(const std::string& name) {
    return envPath(name) + "/services";
}

bool ContainerManager::writeTemplateRecord(const std::string& name, const std::string& templateName) {
    std::string path = templateRecordPath(name);
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        PLOG(ERROR) << "writeTemplateRecord " << path;
        return false;
    }
    write(fd, templateName.data(), templateName.size());
    write(fd, "\n", 1);
    close(fd);
    return true;
}

std::string ContainerManager::readTemplateRecord(const std::string& name) {
    std::string path = templateRecordPath(name);
    std::ifstream in(path.c_str());
    if (!in) return "";
    std::string line;
    if (!std::getline(in, line)) return "";
    return android::base::Trim(line);
}

std::string ContainerManager::firstTemplateTarInTemplateDir() {
    DIR* dir = opendir(TEMPLATE_DIR);
    if (!dir) return "";
    std::string tpl;
    struct dirent* e;
    while ((e = readdir(dir)) != nullptr) {
        std::string fn(e->d_name);
        if (fn.size() > 7 && fn.substr(fn.size() - 7) == ".tar.gz") {
            tpl = std::string(TEMPLATE_DIR) + "/" + fn;
            break;
        }
    }
    closedir(dir);
    return tpl;
}

std::vector<std::string> ContainerManager::listContainers() {
    std::vector<std::string> result;
    DIR* dir = opendir(CONTAINER_BASE_DIR);
    if (!dir) return result;
    struct dirent* entry;
    while ((entry = readdir(dir)) != nullptr) {
        if (entry->d_type == DT_DIR && entry->d_name[0] != '.') {
            std::string rootfs = rootfsPath(entry->d_name);
            struct stat st;
            if (stat(rootfs.c_str(), &st) == 0 && S_ISDIR(st.st_mode)) {
                result.emplace_back(entry->d_name);
            }
        }
    }
    closedir(dir);
    return result;
}

bool ContainerManager::extractTemplate(const std::string& templateTarGz, const std::string& destDir) {
    std::string err;
    if (!extractTarGz(templateTarGz, destDir, &err)) {
        mLastError_ = err.empty() ? "template extract failed" : err;
        LOG(ERROR) << mLastError_;
        return false;
    }
    return true;
}

bool ContainerManager::createContainer(const std::string& name, const std::string& templateName) {
    mLastError_.clear();
    std::string env = envPath(name);
    std::string rootfs = rootfsPath(name);

    struct stat st;
    if (stat(rootfs.c_str(), &st) == 0) {
        mLastError_ = "container already exists: " + name;
        LOG(WARNING) << mLastError_;
        return false;
    }

    if (mkdir(env.c_str(), 0755) != 0 && errno != EEXIST) {
        mLastError_ = std::string("mkdir ") + env + ": " + strerror(errno);
        PLOG(ERROR) << mLastError_;
        return false;
    }

    std::string tpl = templatePath(templateName);
    if (stat(tpl.c_str(), &st) != 0) {
        mLastError_ = "template not found: " + tpl;
        LOG(ERROR) << mLastError_;
        return false;
    }

    if (!extractTemplate(tpl, rootfs)) {
        return false;
    }

    mkdir((rootfs + "/proc").c_str(), 0555);
    mkdir((rootfs + "/dev").c_str(), 0755);
    mkdir((rootfs + "/dev/pts").c_str(), 0755);
    mkdir((rootfs + "/sys").c_str(), 0555);
    mkdir((rootfs + "/sdcard").c_str(), 0755);
    mkdir((rootfs + "/tmp").c_str(), 01777);

    std::string resolv = rootfs + "/etc/resolv.conf";
    int fd = open(resolv.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        const char* dns = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n";
        write(fd, dns, strlen(dns));
        close(fd);
    }

    if (!writeTemplateRecord(name, templateName)) {
        mLastError_ = "failed to write .template record";
        return false;
    }

    if (!mCgroup_.createForContainer(name)) {
        LOG(WARNING) << "cgroup create failed for " << name << " (continuing without limits)";
    }
    mUnits_->forgetEnv(name);
    mUnits_->writeEnvName(name);

    LOG(INFO) << "Container " << name << " created from template " << templateName;
    return true;
}

static int removePathRecursive(const std::string& path) {
    struct stat st;
    if (lstat(path.c_str(), &st) != 0) {
        return errno == ENOENT ? 0 : -1;
    }
    if (S_ISDIR(st.st_mode)) {
        DIR* d = opendir(path.c_str());
        if (!d) return -1;
        while (struct dirent* e = readdir(d)) {
            if (!strcmp(e->d_name, ".") || !strcmp(e->d_name, "..")) continue;
            if (removePathRecursive(path + "/" + e->d_name) != 0) {
                closedir(d);
                return -1;
            }
        }
        closedir(d);
        if (rmdir(path.c_str()) != 0 && errno != ENOENT) return -1;
        return 0;
    }
    if (unlink(path.c_str()) != 0 && errno != ENOENT) return -1;
    return 0;
}

static int recursiveRemove(const std::string& path) { return removePathRecursive(path); }

/** Unmount every mount point under {@code rootfs} (deepest first). Needed when fixed-path
 *  teardownBindMounts misses a bind mount or a previous umount failed — otherwise rmdir(rootfs)
 *  fails with EBUSY/ENOTEMPTY. */
static void umountAllUnderRootfs(const std::string& rootfs) {
    if (rootfs.empty()) return;
    FILE* fp = setmntent("/proc/mounts", "r");
    if (!fp) {
        PLOG(WARNING) << "setmntent /proc/mounts";
        return;
    }
    std::vector<std::string> mounts;
    struct mntent* e;
    while ((e = getmntent(fp)) != nullptr) {
        std::string mp(e->mnt_dir);
        if (mp.empty()) continue;
        if (mp == rootfs ||
            (mp.size() > rootfs.size() && mp[rootfs.size()] == '/' &&
             mp.compare(0, rootfs.size(), rootfs) == 0)) {
            mounts.push_back(std::move(mp));
        }
    }
    endmntent(fp);
    std::sort(mounts.begin(), mounts.end(), [](const std::string& a, const std::string& b) {
        return a.size() > b.size();
    });
    for (const auto& mp : mounts) {
        if (umount2(mp.c_str(), MNT_DETACH) != 0 && errno != EINVAL && errno != ENOENT) {
            PLOG(WARNING) << "umount2 " << mp;
        }
    }
}

void ContainerManager::killContainerProcesses(const std::string& rootfs) {
    DIR* proc = opendir("/proc");
    if (!proc) return;
    struct dirent* entry;
    while ((entry = readdir(proc)) != nullptr) {
        if (entry->d_type != DT_DIR) continue;
        char* endp;
        long pid = strtol(entry->d_name, &endp, 10);
        if (*endp != '\0' || pid <= 1) continue;

        char link[PATH_MAX];
        std::string rootLink = std::string("/proc/") + entry->d_name + "/root";
        ssize_t len = readlink(rootLink.c_str(), link, sizeof(link) - 1);
        if (len <= 0) continue;
        link[len] = '\0';
        if (std::string(link).find(rootfs) == 0) {
            kill(static_cast<pid_t>(pid), SIGKILL);
        }
    }
    closedir(proc);
    usleep(100000);
}

std::string ContainerManager::envOfPid(pid_t pid) {
    if (pid <= 1) return "";
    char link[PATH_MAX];
    std::string rootLink = "/proc/" + std::to_string(pid) + "/root";
    ssize_t len = readlink(rootLink.c_str(), link, sizeof(link) - 1);
    if (len <= 0) return "";
    link[len] = '\0';
    std::string root(link);
    for (const auto& name : listContainers()) {
        const std::string rootfs = rootfsPath(name);
        if (root == rootfs || root.compare(0, rootfs.size() + 1, rootfs + "/") == 0) return name;
    }
    return "";
}

bool ContainerManager::teardownBindMounts(const std::string& rootfs) {
    const char* mounts[] = {
            "/etc/resolv.conf",
            "/opt/udagen/workspace",
            "/opt/openclaw-dev",
            "/root/.npm",
            "/proc",
            "/dev/pts",
            "/dev/shm",
            "/dev",
            "/sys",
            "/sdcard",
    };
    bool ok = true;
    for (size_t i = 0; i < sizeof(mounts) / sizeof(mounts[0]); ++i) {
        std::string target = rootfs + mounts[i];
        if (umount2(target.c_str(), MNT_DETACH) != 0 && errno != EINVAL && errno != ENOENT) {
            PLOG(WARNING) << "umount " << target;
            ok = false;
        }
    }
    return ok;
}

bool ContainerManager::destroyContainer(const std::string& name) {
    mLastError_.clear();
    mUnits_->forgetEnv(name);
    dropEnvNs(name);
    {
        std::lock_guard<std::mutex> lock(mWorkDirMutex_);
        mWorkDir_.erase(name);
    }
    std::string rootfs = rootfsPath(name);
    std::string env = envPath(name);

    bool removed = false;
    for (int attempt = 0; attempt < 5; ++attempt) {
        if (attempt > 0) {
            usleep(200000);
        }
        killContainerProcesses(rootfs);
        teardownBindMounts(rootfs);
        umountAllUnderRootfs(rootfs);
        mCgroup_.destroyForContainer(name);

        if (recursiveRemove(env) == 0) {
            removed = true;
            break;
        }
        PLOG(WARNING) << "destroyContainer: recursiveRemove failed attempt " << (attempt + 1) << " for "
                      << env;
    }
    if (!removed) {
        mLastError_ = "Failed to remove " + env + " (busy mount or unreleased file; check logcat aohp-containerd)";
        LOG(ERROR) << mLastError_;
        return false;
    }
    LOG(INFO) << "Container " << name << " destroyed";
    return true;
}

bool ContainerManager::resetContainer(const std::string& name) {
    mUnits_->forgetEnv(name);
    dropEnvNs(name);
    {
        std::lock_guard<std::mutex> lock(mWorkDirMutex_);
        mWorkDir_.erase(name);
    }
    std::string rootfs = rootfsPath(name);
    std::string env = envPath(name);

    killContainerProcesses(rootfs);
    teardownBindMounts(rootfs);
    umountAllUnderRootfs(rootfs);
    if (recursiveRemove(rootfs) != 0) {
        LOG(ERROR) << "reset: failed to remove rootfs " << rootfs;
        return false;
    }

    std::string tpl;
    std::string recorded = readTemplateRecord(name);
    if (!recorded.empty()) {
        tpl = templatePath(recorded);
        struct stat st;
        if (stat(tpl.c_str(), &st) != 0) {
            LOG(WARNING) << "recorded template missing, falling back: " << tpl;
            tpl.clear();
        }
    }
    if (tpl.empty()) {
        tpl = firstTemplateTarInTemplateDir();
    }
    if (tpl.empty()) {
        LOG(ERROR) << "No template found for reset";
        return false;
    }

    if (!extractTemplate(tpl, rootfs)) {
        return false;
    }

    mkdir((rootfs + "/proc").c_str(), 0555);
    mkdir((rootfs + "/dev").c_str(), 0755);
    mkdir((rootfs + "/dev/pts").c_str(), 0755);
    mkdir((rootfs + "/sys").c_str(), 0555);
    mkdir((rootfs + "/sdcard").c_str(), 0755);
    mkdir((rootfs + "/tmp").c_str(), 01777);

    std::string resolv = rootfs + "/etc/resolv.conf";
    int fd = open(resolv.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd >= 0) {
        const char* dns = "nameserver 8.8.8.8\nnameserver 8.8.4.4\n";
        write(fd, dns, strlen(dns));
        close(fd);
    }

    mCgroup_.destroyForContainer(name);
    mCgroup_.createForContainer(name);
    mUnits_->writeEnvName(name);

    LOG(INFO) << "Container " << name << " reset";
    return true;
}

// Android mounts /data nosuid,nodev and every env's rootfs lives under /data/aohp, so setuid
// programs (sudo, su, ...) run without privilege in every env ("effective uid is not 0").
// In this child's private mount namespace, bind the rootfs onto itself and clear only
// MOUNT_ATTR_NOSUID on that bind with mount_setattr(2) (Linux 5.12+). The host's /data mount is
// untouched, and a setuid-root program in the env still gets only this domain's capability
// bounding set and SELinux context, i.e. what env root already has. mount_setattr() goes through
// no LSM remount hook, so no labeledfs:filesystem remount grant is needed (MS_REMOUNT would);
// the self-bind needs aohp_container_data_file:dir mounton, which the policy already has.
// Best effort: if either step fails the env runs as before, just without setuid.
// Enter the rootfs with pivot_root(2), chroot(2) as the fallback. A pivoted root is the mount
// namespace's root, so the kernel's "chrooted" checks pass: create_user_ns() refuses a chrooted
// caller, which is why unshare(CLONE_NEWUSER) failed EPERM in every env (2026-11-09). Needs the
// rootfs to be a mount point, which allowSetuidInRootfs()' self-bind provides. pivot_root(".", ".")
// stacks the old root on top of the new one; the lazy unmount drops it (runc does the same).
static bool enterRootfs(const std::string& rootfs) {
    if (chdir(rootfs.c_str()) == 0 && syscall(__NR_pivot_root, ".", ".") == 0) {
        if (umount2(".", MNT_DETACH) != 0) PLOG(WARNING) << "detach old root after pivot_root";
        if (chdir("/") != 0) PLOG(WARNING) << "chdir / after pivot_root";
        return true;
    }
    PLOG(WARNING) << "pivot_root " << rootfs << " failed; falling back to chroot";
    if (chroot(rootfs.c_str()) != 0) {
        PLOG(ERROR) << "chroot " << rootfs;
        return false;
    }
    if (chdir("/") != 0) PLOG(WARNING) << "chdir / after chroot";
    return true;
}


// Record the directory tree (and symlinks) of <rootfs>/run before covering it, then rebuild it on
// the tmpfs with the same modes and owners. Regular files, sockets and fifos are runtime state and
// stay behind. Depth-limited: the persistent /run only ever holds a shallow skeleton.
static void collectRunSkeleton(const std::string& base, const std::string& rel, int depth,
                               std::vector<std::tuple<std::string, mode_t, uid_t, gid_t, std::string>>* out) {
    if (depth > 4) return;
    DIR* d = opendir((base + rel).c_str());
    if (!d) return;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        std::string n = e->d_name;
        if (n == "." || n == "..") continue;
        std::string r = rel + "/" + n;
        struct stat st;
        if (lstat((base + r).c_str(), &st) != 0) continue;
        if (S_ISLNK(st.st_mode)) {
            char buf[PATH_MAX];
            ssize_t len = readlink((base + r).c_str(), buf, sizeof(buf) - 1);
            if (len > 0) out->emplace_back(r, st.st_mode, st.st_uid, st.st_gid, std::string(buf, len));
        } else if (S_ISDIR(st.st_mode)) {
            // Skip trees that belong to the runtimes themselves: they are exactly what must be
            // empty after a reboot.
            if (rel.empty() && (n == "containers" || n == "libpod" || n == "crun" || n == "netns" ||
                                n == "runc" || n == "user"))
                continue;
            out->emplace_back(r, st.st_mode, st.st_uid, st.st_gid, "");
            collectRunSkeleton(base, r, depth + 1, out);
        }
    }
    closedir(d);
}

static void mountRunTmpfs(const std::string& rootfs) {
    std::string run = rootfs + "/run";
    struct stat st;
    if (stat(run.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return;
    std::vector<std::tuple<std::string, mode_t, uid_t, gid_t, std::string>> skel;
    collectRunSkeleton(run, "", 0, &skel);
    if (mount("tmpfs", run.c_str(), "tmpfs", MS_NOSUID | MS_NODEV, "mode=0755,size=10%") != 0) {
        PLOG(WARNING) << "tmpfs mount on /run failed (runtime state persists across reboots)";
        return;
    }
    for (const auto& ent : skel) {
        const std::string path = run + std::get<0>(ent);
        if (!std::get<4>(ent).empty()) {
            if (symlink(std::get<4>(ent).c_str(), path.c_str()) != 0 && errno != EEXIST)
                PLOG(WARNING) << "run skeleton symlink " << path;
            continue;
        }
        if (mkdir(path.c_str(), std::get<1>(ent) & 07777) != 0 && errno != EEXIST) {
            PLOG(WARNING) << "run skeleton mkdir " << path;
            continue;
        }
        chmod(path.c_str(), std::get<1>(ent) & 07777);
        if (std::get<2>(ent) != 0 || std::get<3>(ent) != 0) {
            if (lchown(path.c_str(), std::get<2>(ent), std::get<3>(ent)) != 0) PLOG(WARNING) << "run skeleton chown " << path;
        }
    }
    // /run/user/0 is XDG_RUNTIME_DIR for the env's root session (Wayland, dbus session, pipewire).
    mkdir((run + "/user").c_str(), 0755);
    mkdir((run + "/user/0").c_str(), 0700);
    // /run/lock is 1777 on Debian.
    mkdir((run + "/lock").c_str(), 01777);
    chmod((run + "/lock").c_str(), 01777);
}

static void allowSetuidInRootfs(const std::string& rootfs) {
    if (mount(rootfs.c_str(), rootfs.c_str(), nullptr, MS_BIND, nullptr) != 0) {
        PLOG(WARNING) << "self-bind " << rootfs << " (for setuid) failed";
        return;
    }
    struct mount_attr attr = {};
    attr.attr_clr = MOUNT_ATTR_NOSUID;
    if (syscall(__NR_mount_setattr, AT_FDCWD, rootfs.c_str(), 0, &attr, sizeof(attr)) != 0) {
        PLOG(WARNING) << "mount_setattr(clear nosuid) " << rootfs << " failed";
    }
}

bool ContainerManager::setupBindMounts(const std::string& rootfs) {
    allowSetuidInRootfs(rootfs);

    auto doMount = [&](const char* src, const char* rel, unsigned long flags) -> bool {
        std::string target = rootfs + rel;
        if (!ensureDir(target, 0755)) return false;
        if (mount(src, target.c_str(), nullptr, MS_BIND | flags, nullptr) != 0) {
            PLOG(ERROR) << "bind mount " << src << " -> " << target;
            return false;
        }
        return true;
    };

    // Android mounts the host /proc with hidepid=invisible,gid=readproc: a bind of it hides
    // every pid the container is not in group readproc for (ls /proc shows ~10 entries,
    // /proc/<pid>/stat is ENOENT), so ps/pidof/pgrep and pid-liveness checks inside the
    // container cannot see host processes. Mount a fresh procfs instance (own superblock
    // since Linux 5.8, so its options are independent of the host mount) without hidepid;
    // SELinux still governs which /proc/<pid> entries are readable. Fall back to the bind
    // if the kernel or policy refuses.
    {
        std::string target = rootfs + "/proc";
        if (!ensureDir(target, 0555)) return false;
        if (mount("proc", target.c_str(), "proc", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0) {
            PLOG(WARNING) << "fresh procfs mount failed; falling back to bind of host /proc";
            if (!doMount("/proc", "/proc", 0)) return false;
        }
    }
    if (!doMount("/dev", "/dev", 0)) return false;
    if (!doMount("/sys", "/sys", MS_RDONLY)) return false;

    // cgroup v2 for OCI runtimes in the env (podman/crun, 2026-11-09). The /sys bind above is
    // non-recursive, so /sys/fs/cgroup is an empty sysfs directory and crun refuses it ("invalid
    // file system type"). Mount a cgroup2 instance over it: the host-wide hierarchy for now, so a
    // runtime's containers land in /libpod_parent next to this env's own group, with memory/pids
    // delegated from the root at daemon start (CgroupController::loadConfig). A per-env cgroup
    // namespace needs an anchor the daemon keeps alive; follow-up.
    {
        std::string cgt = rootfs + "/sys/fs/cgroup";
        if (ensureDir(cgt, 0555) &&
            mount("cgroup2", cgt.c_str(), "cgroup2", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0) {
            PLOG(WARNING) << "cgroup2 mount in env failed (OCI runtimes in the env will not start)";
        }
    }
    // POSIX message queues: glibc's mq_open() needs /dev/mqueue (aohp-containerd.rc creates the
    // directory on the host /dev that is bound above); one mqueue instance per ipc namespace.
    {
        std::string mq = rootfs + "/dev/mqueue";
        struct stat mqst;
        if (stat(mq.c_str(), &mqst) == 0 && S_ISDIR(mqst.st_mode)) {
            if (mount("mqueue", mq.c_str(), "mqueue", MS_NOSUID | MS_NODEV | MS_NOEXEC, nullptr) != 0) {
                PLOG(WARNING) << "mqueue mount on /dev/mqueue failed (POSIX mq in env will not work)";
            }
        }
    }

    std::string devpts = rootfs + "/dev/pts";
    if (!ensureDir(devpts, 0755)) return false;
    if (mount("devpts", devpts.c_str(), "devpts", 0, "newinstance,ptmxmode=0666") != 0) {
        PLOG(WARNING) << "devpts mount failed (PTY in container may not work)";
    }

    // POSIX shared memory: glibc's shm_open() needs /dev/shm, which Android lacks. The bind of the host
    // /dev brings in the (empty) /dev/shm directory aohp-containerd.rc creates; give each container its
    // own private tmpfs there (this mount namespace is a slave, so it never shows on the host). Capped at
    // a quarter of RAM like Debian's default; files are labelled aohp_container_daemon_tmpfs by the
    // tmpfs_domain transition, so the Termux:X11 app may map what the env shares with it.
    std::string devshm = rootfs + "/dev/shm";
    struct stat shmst;
    if (stat(devshm.c_str(), &shmst) == 0 && S_ISDIR(shmst.st_mode)) {
        if (mount("tmpfs", devshm.c_str(), "tmpfs", MS_NOSUID | MS_NODEV, "mode=1777,size=25%") != 0) {
            PLOG(WARNING) << "tmpfs mount on /dev/shm failed (POSIX shm in container will not work)";
        }
    } else {
        LOG(WARNING) << "no /dev/shm on the host (aohp-containerd.rc should create it); POSIX shm unavailable";
    }

    // /run is a tmpfs on every Linux distribution: runtime state that must not outlive a boot. The
    // env's persistent /run made podman refuse to start after a phone reboot ("boot ID differs from
    // cached boot ID", /run/libpod and /run/containers/storage) and left stale pid/lock files for
    // sshd, dbus, tailscaled. Mount a tmpfs there (the mount namespace is now per env, so it lives
    // as long as the env is up) and recreate the directory skeleton underneath - Debian's
    // tmpfiles.d equivalent; the units already mkdir their own runtime dirs on start.
    mountRunTmpfs(rootfs);

    struct stat st;
    if (stat("/sdcard", &st) == 0) {
        doMount("/sdcard", "/sdcard", 0);
    } else if (stat("/storage/emulated/0", &st) == 0) {
        doMount("/storage/emulated/0", "/sdcard", 0);
    }

    if (stat(SHARED_NPM_CACHE, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (ensureDir(rootfs + "/root", 0755) && ensureDir(rootfs + "/root/.npm", 0755)) {
            if (mount(SHARED_NPM_CACHE, (rootfs + "/root/.npm").c_str(), nullptr, MS_BIND, nullptr) !=
                0) {
                PLOG(WARNING) << "bind mount npm cache failed";
            }
        }
    }
    if (stat(SHARED_OPENCLAW_DEV, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (ensureDir(rootfs + "/opt", 0755) && ensureDir(rootfs + "/opt/openclaw-dev", 0755)) {
            if (mount(SHARED_OPENCLAW_DEV, (rootfs + "/opt/openclaw-dev").c_str(), nullptr,
                      MS_BIND, nullptr) != 0) {
                PLOG(WARNING) << "bind mount openclaw-dev failed";
            }
        }
    }
    if (stat(SHARED_UDA, &st) == 0 && S_ISDIR(st.st_mode)) {
        if (ensureDir(rootfs + "/opt/udagen", 0755) &&
            ensureDir(rootfs + "/opt/udagen/workspace", 0755)) {
            if (mount(SHARED_UDA, (rootfs + "/opt/udagen/workspace").c_str(), nullptr, MS_BIND,
                      nullptr) != 0) {
                PLOG(WARNING) << "bind mount uda workspace failed";
            }
        }
    }
    // Use Android host DNS (netd on 127.0.0.1); template resolv.conf (8.8.8.8) often fails in chroot.
    if (stat("/etc/resolv.conf", &st) == 0 && S_ISREG(st.st_mode)) {
        std::string target = rootfs + "/etc/resolv.conf";
        if (ensureDir(rootfs + "/etc", 0755)) {
            if (mount("/etc/resolv.conf", target.c_str(), nullptr, MS_BIND | MS_RDONLY,
                      nullptr) != 0) {
                PLOG(WARNING) << "bind mount resolv.conf failed";
            }
        }
    }
    return true;
}

// ---- per-env mount namespace ---------------------------------------------------------------------
// Each entry into an env (unit start, "aohp sandbox exec", shell) used to build its own mount
// namespace: unshare, make-rslave, binds, pivot_root. A mount made by one entry was invisible to
// the next, which broke everything that mounts for later: podman's /run/netns/<id> nsfs binds
// (netavark's teardown, run from a later entry, opened the bare placeholder file, got setns EINVAL
// and left its DNAT rules behind - a published port then answered "No route to host" once another
// container reused it, 2026-11-09), the "per container" /dev/shm tmpfs that was really per entry
// (two units could not share POSIX shm), and the cgroup2 / mqueue / devpts instances mounted anew
// each time. Now the first entry builds the namespace and the daemon pins it with an fd on
// /proc/<child>/ns/mnt; every later entry setns(2)s into it. The pin keeps the namespace and its
// mounts alive with zero processes; destroy/reset drop it; after a daemon restart
// adoptOrphanServicePids() re-pins from a surviving unit pid.

int ContainerManager::envNsFd(const std::string& name) {
    std::lock_guard<std::mutex> lock(mEnvNsMutex_);
    auto it = mEnvNsFd_.find(name);
    return it == mEnvNsFd_.end() ? -1 : it->second;
}

void ContainerManager::pinEnvNs(const std::string& name, pid_t pid) {
    std::string p = "/proc/" + std::to_string(pid) + "/ns/mnt";
    int fd = open(p.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        PLOG(WARNING) << "env " << name << ": pin mount namespace " << p;
        return;
    }
    std::lock_guard<std::mutex> lock(mEnvNsMutex_);
    if (mEnvNsFd_.count(name)) {
        // Two first entries raced; the one pinned already wins, the other namespace is one-off.
        close(fd);
        return;
    }
    mEnvNsFd_[name] = fd;
    LOG(INFO) << "env " << name << ": mount namespace pinned from pid " << pid;
}

void ContainerManager::dropEnvNs(const std::string& name) {
    std::lock_guard<std::mutex> lock(mEnvNsMutex_);
    auto it = mEnvNsFd_.find(name);
    if (it == mEnvNsFd_.end()) return;
    close(it->second);
    mEnvNsFd_.erase(it);
    LOG(INFO) << "env " << name << ": mount namespace dropped";
}

// Daemon restart: the pins are gone but unit processes may still run in the old namespace. Adopt
// it from the first live env pid so later entries see the same mounts. HostExec units share the
// daemon's own mount namespace and are skipped.
void ContainerManager::repinEnvNsFromPid(const std::string& name, pid_t pid) {
    if (envNsFd(name) >= 0) return;
    char self[64], other[64];
    std::string p = "/proc/" + std::to_string(pid) + "/ns/mnt";
    ssize_t a = readlink("/proc/self/ns/mnt", self, sizeof(self) - 1);
    ssize_t b = readlink(p.c_str(), other, sizeof(other) - 1);
    if (a <= 0 || b <= 0) return;
    self[a] = '\0';
    other[b] = '\0';
    if (strcmp(self, other) == 0) return;
    pinEnvNs(name, pid);
}

bool ContainerManager::childEnterEnv(const std::string& rootfs, int pinnedFd, int readyFd, int goFd) {
    char what = 'N';
    if (pinnedFd >= 0 && setns(pinnedFd, CLONE_NEWNS) == 0) {
        // setns(CLONE_NEWNS) moves root and cwd to the namespace's root. When the first entry had to
        // fall back to chroot that root is still the host's; the rootfs path then resolves and we
        // chroot like it did.
        struct stat st;
        if (stat(rootfs.c_str(), &st) == 0 && S_ISDIR(st.st_mode) && chroot(rootfs.c_str()) != 0) {
            PLOG(ERROR) << "chroot " << rootfs << " after joining the env mount namespace";
            return false;
        }
        if (chdir("/") != 0) PLOG(WARNING) << "chdir / after joining the env mount namespace";
        what = 'J';
    } else {
        if (pinnedFd >= 0) PLOG(WARNING) << "setns(env mount namespace) failed; building a new one";
        tryUnshareMountNs();
        if (!setupBindMounts(rootfs)) return false;
        if (!enterRootfs(rootfs)) return false;
    }
    if (readyFd >= 0) {
        TEMP_FAILURE_RETRY(write(readyFd, &what, 1));
        close(readyFd);
    }
    if (goFd >= 0) {
        char go = 0;
        TEMP_FAILURE_RETRY(read(goFd, &go, 1));
        close(goFd);
    }
    return true;
}

void ContainerManager::parentAdmitEnv(const std::string& name, pid_t pid, int readyFd, int goFd) {
    char what = 0;
    ssize_t n = TEMP_FAILURE_RETRY(read(readyFd, &what, 1));
    close(readyFd);
    if (n == 1) {
        // Before the go byte the child has not exec'd, so every descendant inherits this membership.
        mCgroup_.joinContainerCgroup(name, pid);
        mCgroup_.joinCpuset(pid);
        if (what == 'N') pinEnvNs(name, pid);
    }
    char go = 1;
    TEMP_FAILURE_RETRY(write(goFd, &go, 1));
    close(goFd);
}

int ContainerManager::forkIntoContainer(const std::string& containerName, const std::string& rootfs,
                                       const char* const argv[], bool usePty) {
    int masterFd = -1;
    int pipeFds[2] = {-1, -1};

    if (!usePty) {
        if (pipe(pipeFds) < 0) {
            PLOG(ERROR) << "pipe";
            return -1;
        }
    }

    int readyPipe[2], goPipe[2];
    if (pipe2(readyPipe, O_CLOEXEC) != 0 || pipe2(goPipe, O_CLOEXEC) != 0) {
        PLOG(ERROR) << "pipe2";
        if (!usePty) {
            close(pipeFds[0]);
            close(pipeFds[1]);
        }
        return -1;
    }
    const int pinnedFd = envNsFd(containerName);

    pid_t pid;
    if (usePty) {
        pid = forkpty(&masterFd, nullptr, nullptr, nullptr);
    } else {
        pid = fork();
    }

    if (pid < 0) {
        PLOG(ERROR) << "fork/forkpty";
        return -1;
    }

    if (pid == 0) {
        close(readyPipe[0]);
        close(goPipe[1]);
        if (!childEnterEnv(rootfs, pinnedFd, readyPipe[1], goPipe[0])) {
            _exit(125);
        }

        setContainerChildCommonEnv();

        if (!usePty) {
            close(pipeFds[0]);
            dup2(pipeFds[1], STDOUT_FILENO);
            dup2(pipeFds[1], STDERR_FILENO);
            close(pipeFds[1]);
        }

        execvp(argv[0], const_cast<char* const*>(argv));
        _exit(127);
    }

    close(readyPipe[1]);
    close(goPipe[0]);
    parentAdmitEnv(containerName, pid, readyPipe[0], goPipe[1]);

    if (usePty) {
        return masterFd;
    }
    close(pipeFds[1]);
    return pipeFds[0];
}

ExecResult ContainerManager::execSync(const std::string& name, const std::string& command,
                                      int timeoutMs) {
    ExecResult result{-1, "", ""};
    std::string rootfs = rootfsPath(name);

    struct stat st;
    if (stat(rootfs.c_str(), &st) != 0) {
        result.stderrStr = "Container not found: " + name;
        return result;
    }

    std::string workDir = "/";
    {
        std::lock_guard<std::mutex> lock(mWorkDirMutex_);
        auto it = mWorkDir_.find(name);
        if (it != mWorkDir_.end() && !it->second.empty() && it->second[0] == '/') {
            workDir = it->second;
        }
    }

    int stdoutPipe[2], stderrPipe[2], readyPipe[2], goPipe[2];
    if (pipe(stdoutPipe) < 0 || pipe(stderrPipe) < 0 || pipe2(readyPipe, O_CLOEXEC) < 0 ||
        pipe2(goPipe, O_CLOEXEC) < 0) {
        result.stderrStr = "pipe() failed";
        return result;
    }
    const int pinnedFd = envNsFd(name);

    pid_t pid = fork();
    if (pid < 0) {
        result.stderrStr = "fork() failed";
        return result;
    }

    if (pid == 0) {
        close(stdoutPipe[0]);
        close(stderrPipe[0]);
        close(readyPipe[0]);
        close(goPipe[1]);

        if (!childEnterEnv(rootfs, pinnedFd, readyPipe[1], goPipe[0])) {
            const char* msg = "aohp-containerd: entering the env failed\n";
            write(stderrPipe[1], msg, strlen(msg));
            _exit(125);
        }

        setContainerChildCommonEnv();

        dup2(stdoutPipe[1], STDOUT_FILENO);
        dup2(stderrPipe[1], STDERR_FILENO);
        close(stdoutPipe[1]);
        close(stderrPipe[1]);

        setenv("AOHP_WD", workDir.c_str(), 1);
        setenv("AOHP_CMD", command.c_str(), 1);
        const char* argv[] = {
                "/bin/sh",
                "-c",
                "cd \"${AOHP_WD}\" 2>/dev/null || cd /; "
                "eval \"${AOHP_CMD}\"; ec=$?; "
                "pwd > /tmp/.aohp_lastpwd; "
                "exit $ec",
                nullptr,
        };
        execvp(argv[0], const_cast<char* const*>(argv));
        _exit(127);
    }

    close(stdoutPipe[1]);
    close(stderrPipe[1]);
    close(readyPipe[1]);
    close(goPipe[0]);
    parentAdmitEnv(name, pid, readyPipe[0], goPipe[1]);

    auto readAll = [](int fd) -> std::string {
        std::string out;
        char buf[4096];
        ssize_t n;
        while ((n = read(fd, buf, sizeof(buf))) > 0) {
            out.append(buf, n);
        }
        close(fd);
        return out;
    };

    result.stdoutStr = readAll(stdoutPipe[0]);
    result.stderrStr = readAll(stderrPipe[0]);

    int status = 0;
    if (timeoutMs > 0) {
        alarm(timeoutMs / 1000 + 1);
    }
    waitpid(pid, &status, 0);
    alarm(0);

    result.exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;

    std::string pwdFile = rootfs + "/tmp/.aohp_lastpwd";
    std::ifstream in(pwdFile.c_str());
    std::string line;
    if (std::getline(in, line)) {
        std::string p = android::base::Trim(line);
        if (!p.empty() && p[0] == '/') {
            std::lock_guard<std::mutex> lock(mWorkDirMutex_);
            mWorkDir_[name] = std::move(p);
        }
    }

    return result;
}

int ContainerManager::openShell(const std::string& name) {
    std::string rootfs = rootfsPath(name);
    struct stat st;
    if (stat(rootfs.c_str(), &st) != 0) {
        LOG(ERROR) << "Container not found: " << name;
        return -1;
    }

    const char* argv[] = {"/bin/sh", "-l", nullptr};
    return forkIntoContainer(name, rootfs, argv, true);
}

std::string ContainerManager::templateInfo(const std::string& name) {
    return readTemplateRecord(name);
}

bool ContainerManager::isValidServiceId(const std::string& id) {
    if (id.empty() || id.size() > 64) return false;
    for (char c : id) {
        if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') ||
              c == '-' || c == '_')) {
            return false;
        }
    }
    return true;
}

long ContainerManager::startService(const std::string& name, const std::string& serviceId,
                                    const std::string& command) {
    mLastError_.clear();
    if (!isValidServiceId(serviceId)) {
        mLastError_ = "invalid serviceId";
        return -1;
    }
    // Units (unit_manager.h): <serviceId>.service from /etc/aohp/system when it exists, else a
    // transient unit — supervised, same list/log as the rest.
    {
        std::string err;
        long pid = mUnits_->legacyStartService(name, serviceId, command, &err);
        if (pid < 0) mLastError_ = err;
        return pid;
    }
}

bool ContainerManager::stopService(const std::string& name, const std::string& serviceId) {
    if (!isValidServiceId(serviceId)) return false;
    if (mUnits_->legacyStopService(name, serviceId)) return true;
    // fall through: a service started by a pre-units daemon (pid file) may still be around
    std::string pidPath = servicesDirPath(name) + "/" + serviceId + ".pid";
    std::ifstream in(pidPath.c_str());
    std::string line;
    if (!std::getline(in, line)) {
        return false;
    }
    pid_t p = static_cast<pid_t>(strtol(line.c_str(), nullptr, 10));
    if (p <= 1) return false;
    // Signal the service's process group (startService puts the child in its own), not
    // just the "sh -c" wrapper: killing only the wrapper orphaned the real server (node
    // gateway) which kept its port, so Stop/Restart never freed it. Fall back to the pid
    // alone if no such group exists (service started by an older daemon).
    auto signalService = [p](int sig) -> int {
        if (kill(-p, sig) == 0) return 0;
        return kill(p, sig);
    };
    signalService(SIGTERM);
    usleep(500000);
    if (signalService(0) == 0) {
        usleep(1500000);
        if (signalService(0) == 0) signalService(SIGKILL);
    }
    unlink(pidPath.c_str());
    return true;
}

std::string ContainerManager::listServicesJson(const std::string& name) {
    return mUnits_->legacyListJson(name);
}

// Pre-units listing (pid/meta files under env/services); kept for reference, unused.
[[maybe_unused]] static std::string legacyListServicesJsonFromFiles(const std::string& sdir) {
    DIR* d = opendir(sdir.c_str());
    if (!d) {
        return "[]";
    }
    std::ostringstream oss;
    oss << "[";
    bool first = true;
    struct dirent* e;
    while ((e = readdir(d)) != nullptr) {
        std::string fn(e->d_name);
        if (fn.size() <= 5 || fn.substr(fn.size() - 5) != ".meta") continue;
        std::string sid = fn.substr(0, fn.size() - 5);
        std::string metaPath = sdir + "/" + fn;
        std::ifstream min(metaPath.c_str());
        std::string metaJson;
        if (std::getline(min, metaJson)) {
            metaJson = android::base::Trim(metaJson);
        }
        std::string pidPath = sdir + "/" + sid + ".pid";
        std::ifstream pin(pidPath.c_str());
        std::string pline;
        int pid = -1;
        if (std::getline(pin, pline)) {
            pid = static_cast<int>(strtol(pline.c_str(), nullptr, 10));
        }
        bool alive = (pid > 0 && kill(static_cast<pid_t>(pid), 0) == 0);
        long long startTime = extractJsonIntField(metaJson, "startTime");
        long long uptime = 0;
        if (alive && startTime > 0) {
            uptime = static_cast<long long>(time(nullptr)) - startTime;
        }
        std::string cmd = extractJsonStringField(metaJson, "command");
        if (!first) oss << ",";
        first = false;
        oss << "{\"serviceId\":\"" << jsonEscape(sid) << "\",\"pid\":" << pid
            << ",\"alive\":" << (alive ? "true" : "false") << ",\"startTime\":" << startTime
            << ",\"uptimeSec\":" << uptime << ",\"command\":\"" << jsonEscape(cmd) << "\"}";
    }
    closedir(d);
    oss << "]";
    return oss.str();
}

std::string ContainerManager::serviceLogTail(const std::string& name, const std::string& serviceId,
                                               int tailBytes) {
    if (!isValidServiceId(serviceId)) return "";
    if (tailBytes <= 0 || tailBytes > 4 * 1024 * 1024) tailBytes = 65536;
    {
        std::string unitLog = mUnits_->logTail(name, serviceId, tailBytes);
        struct stat ust;
        if (!unitLog.empty() || stat(UnitManager::unitLogPath(envPath(name), serviceId).c_str(), &ust) == 0) return unitLog;
    }
    std::string path = servicesDirPath(name) + "/" + serviceId + ".log";
    int fd = open(path.c_str(), O_RDONLY);
    if (fd < 0) return "";
    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return "";
    }
    off_t sz = st.st_size;
    off_t off = 0;
    if (sz > tailBytes) {
        off = sz - tailBytes;
    }
    if (lseek(fd, off, SEEK_SET) < 0) {
        close(fd);
        return "";
    }
    std::string out;
    out.resize(static_cast<size_t>(sz - off));
    ssize_t n = read(fd, &out[0], out.size());
    close(fd);
    if (n < 0) return "";
    out.resize(static_cast<size_t>(n));
    return out;
}

std::string ContainerManager::getUsageJson(const std::string& name) {
    return mCgroup_.getUsageJson(name);
}

std::string ContainerManager::diagnose(const std::string& name) {
    std::string tpl = readTemplateRecord(name);
    std::string cg = mCgroup_.diagnoseJson(name);
    struct stat st;
    bool npmHost = stat(SHARED_NPM_CACHE, &st) == 0 && S_ISDIR(st.st_mode);
    bool devHost = stat(SHARED_OPENCLAW_DEV, &st) == 0 && S_ISDIR(st.st_mode);
    std::string rootfs = rootfsPath(name);
    bool rootfsOk = stat(rootfs.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
    std::ostringstream oss;
    oss << "{\"container\":\"" << jsonEscape(name) << "\",\"template\":\"" << jsonEscape(tpl)
        << "\",\"rootfsExists\":" << (rootfsOk ? "true" : "false") << ",\"npmCacheHostDir\":"
        << (npmHost ? "true" : "false") << ",\"openclawDevHostDir\":" << (devHost ? "true" : "false")
        << ",\"cgroup\":" << cg << "}";
    return oss.str();
}

void ContainerManager::adoptOrphanServicePids() {
    std::vector<std::string> envs = listContainers();
    for (const auto& name : envs) {
        std::string sdir = servicesDirPath(name);
        DIR* d = opendir(sdir.c_str());
        if (!d) continue;
        struct dirent* e;
        while ((e = readdir(d)) != nullptr) {
            std::string fn(e->d_name);
            if (fn.size() <= 4 || fn.substr(fn.size() - 4) != ".pid") continue;
            std::string path = sdir + "/" + fn;
            std::ifstream in(path.c_str());
            std::string line;
            if (!std::getline(in, line)) continue;
            int pid = static_cast<int>(strtol(line.c_str(), nullptr, 10));
            if (pid <= 1) {
                unlink(path.c_str());
                continue;
            }
            if (kill(static_cast<pid_t>(pid), 0) != 0) {
                LOG(INFO) << "Removing stale pid file " << path << " for dead pid " << pid;
                unlink(path.c_str());
            } else {
                repinEnvNsFromPid(name, static_cast<pid_t>(pid));
            }
        }
        closedir(d);
    }
}

pid_t ContainerManager::spawnInContainer(const std::string& name, const SpawnSpec& spec, std::string* err) {
    std::string rootfs = rootfsPath(name);
    struct stat st;
    if (stat(rootfs.c_str(), &st) != 0) {
        if (err) *err = "Container not found: " + name;
        return -1;
    }
    if (spec.argv.empty()) {
        if (err) *err = "empty argv";
        return -1;
    }
    int logfd = -1;
    if (!spec.logPath.empty()) {
        logfd = open(spec.logPath.c_str(), O_WRONLY | O_CREAT | O_APPEND | O_CLOEXEC, 0644);
        if (logfd < 0) PLOG(WARNING) << "unit log open " << spec.logPath;
    }
    if (logfd < 0) logfd = open("/dev/null", O_WRONLY | O_CLOEXEC);

    // Build argv/envp before fork: no malloc in the child beyond what the mount setup already does.
    std::vector<char*> argv, envp;
    for (const auto& a : spec.argv) argv.push_back(const_cast<char*>(a.c_str()));
    argv.push_back(nullptr);
    for (const auto& e : spec.env) envp.push_back(const_cast<char*>(e.c_str()));
    envp.push_back(nullptr);

    int syncPipe[2], readyPipe[2], goPipe[2];
    if (pipe2(syncPipe, O_CLOEXEC) != 0 || pipe2(readyPipe, O_CLOEXEC) != 0 ||
        pipe2(goPipe, O_CLOEXEC) != 0) {
        if (err) *err = "pipe failed";
        if (logfd >= 0) close(logfd);
        return -1;
    }
    const int pinnedFd = spec.host ? -1 : envNsFd(name);

    pid_t pid = fork();
    if (pid < 0) {
        if (err) *err = std::string("fork: ") + strerror(errno);
        close(syncPipe[0]);
        close(syncPipe[1]);
        if (logfd >= 0) close(logfd);
        return -1;
    }
    if (pid == 0) {
        close(syncPipe[0]);
        close(readyPipe[0]);
        close(goPipe[1]);
        setsid();
        setpgid(0, 0);
        // stdout/stderr -> log, stdin -> /dev/null
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) {
            dup2(devnull, STDIN_FILENO);
            if (devnull > STDERR_FILENO) close(devnull);
        }
        if (logfd >= 0) {
            dup2(logfd, STDOUT_FILENO);
            dup2(logfd, STDERR_FILENO);
        }
        // close everything else the daemon had open (control socket, client sockets, ptys);
        // O_CLOEXEC fds go away at exec anyway, this catches the rest.
        {
            DIR* fds = opendir("/proc/self/fd");
            if (fds) {
                int dfd = dirfd(fds);
                struct dirent* fe;
                while ((fe = readdir(fds)) != nullptr) {
                    int fd = atoi(fe->d_name);
                    if (fd > STDERR_FILENO && fd != dfd && fd != syncPipe[1] && fd != readyPipe[1] &&
                        fd != goPipe[0] && fd != pinnedFd)
                        close(fd);
                }
                closedir(fds);
            }
        }
        if (spec.host) {
            // Host-exec units join the env's cgroup too (parentAdmitEnv does it): stop/KillMode/restart
            // accounting are the same, and the helper dies with the env.
            const char what = 'H';
            write(readyPipe[1], &what, 1);
            close(readyPipe[1]);
            char go = 0;
            TEMP_FAILURE_RETRY(read(goPipe[0], &go, 1));
            close(goPipe[0]);
        } else if (!childEnterEnv(rootfs, pinnedFd, readyPipe[1], goPipe[0])) {
            const char m = 125;
            write(syncPipe[1], &m, 1);
            _exit(125);
        }
        if (chdir(spec.workDir.c_str()) != 0) {
            if (!spec.workDirOptional) {
                const char m = 124;
                write(syncPipe[1], &m, 1);
                _exit(124);
            }
            chdir("/");
        }
        umask(022);
        execve(argv[0], argv.data(), envp.data());
        const char m = 127;
        write(syncPipe[1], &m, 1);
        _exit(127);
    }
    close(syncPipe[1]);
    close(readyPipe[1]);
    close(goPipe[0]);
    if (logfd >= 0) close(logfd);
    parentAdmitEnv(name, pid, readyPipe[0], goPipe[1]);
    // The pipe closes at exec (O_CLOEXEC) -> read returns 0 on success, or a failure code byte.
    char code = 0;
    ssize_t n = read(syncPipe[0], &code, 1);
    close(syncPipe[0]);
    if (n == 1) {
        int status = 0;
        waitpid(pid, &status, 0);
        if (err) {
            switch (code) {
                case 124: *err = "WorkingDirectory " + spec.workDir + " missing"; break;
                case 125: *err = "entering the env (mount namespace, binds, root) failed"; break;
                default: *err = "exec " + spec.argv[0] + " failed"; break;
            }
        }
        return -1;
    }
    return pid;
}

}  // namespace aohp

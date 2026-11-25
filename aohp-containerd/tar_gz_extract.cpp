/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#define LOG_TAG "aohp-containerd"

#include "tar_gz_extract.h"

#include <cerrno>
#include <climits>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <vector>

#include <android-base/logging.h>
#include <zlib.h>

namespace aohp {

namespace {

static void setErr(std::string* error, const std::string& msg) {
    if (error) *error = msg;
    LOG(ERROR) << msg;
}

static bool readAllFd(int fd, std::vector<uint8_t>* out) {
    out->clear();
    uint8_t buf[65536];
    for (;;) {
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n < 0) return false;
        if (n == 0) break;
        out->insert(out->end(), buf, buf + n);
    }
    return true;
}

static bool gunzipInMemory(const std::vector<uint8_t>& compressed, std::vector<uint8_t>* plain,
                           std::string* error) {
    plain->clear();
    if (compressed.empty()) {
        setErr(error, "empty gzip input");
        return false;
    }

    z_stream strm = {};
    // 16 + MAX_WBITS: gzip wrapper
    if (inflateInit2(&strm, 16 + MAX_WBITS) != Z_OK) {
        setErr(error, "inflateInit2 failed");
        return false;
    }

    strm.next_in = const_cast<Bytef*>(compressed.data());
    strm.avail_in = static_cast<uInt>(compressed.size());
    if (strm.avail_in != compressed.size()) {
        inflateEnd(&strm);
        setErr(error, "gzip input too large for zlib uInt");
        return false;
    }

    int ret;
    uint8_t outchunk[65536];
    do {
        strm.next_out = outchunk;
        strm.avail_out = sizeof(outchunk);
        ret = inflate(&strm, Z_NO_FLUSH);
        if (ret != Z_OK && ret != Z_STREAM_END) {
            inflateEnd(&strm);
            setErr(error, std::string("inflate: ") + (strm.msg ? strm.msg : "unknown"));
            return false;
        }
        size_t have = sizeof(outchunk) - strm.avail_out;
        plain->insert(plain->end(), outchunk, outchunk + have);
    } while (ret != Z_STREAM_END);

    inflateEnd(&strm);
    return true;
}

static bool isZeroBlock(const uint8_t* p) {
    for (int i = 0; i < 512; ++i) {
        if (p[i] != 0) return false;
    }
    return true;
}

static size_t parseOctalField(const char* field, size_t len) {
    size_t v = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned char c = static_cast<unsigned char>(field[i]);
        if (c == 0 || c == ' ') continue;
        if (c < '0' || c > '7') break;
        v = (v << 3) + (c - '0');
    }
    return v;
}

// Owner or group id of an entry. GNU tar writes an id that does not fit the octal field in base-256 (the first
// byte then has its high bit set); a rootfs template has no such ids, so one is read as 0.
static uint32_t parseId(const char* field) {
    if (static_cast<unsigned char>(field[0]) & 0x80) return 0;
    return static_cast<uint32_t>(parseOctalField(field, 8));
}

// Give an entry the owner and group recorded in the tar. There is no user namespace, so the numbers are the
// container's own (/etc/passwd of the template). Call it before chmod: the kernel clears setuid and setgid
// when a file changes owner. A failure is not fatal; the entry stays root-owned.
static void applyOwner(const std::string& path, uint32_t uid, uint32_t gid, int* failures) {
    if (uid == 0 && gid == 0) return;
    if (lchown(path.c_str(), uid, gid) != 0) {
        if ((*failures)++ == 0) PLOG(WARNING) << "lchown " << path << " to " << uid << ":" << gid;
    }
}

static bool pathSafe(const std::string& rel) {
    if (rel.empty()) return false;
    if (rel[0] == '/') return false;
    if (rel.find("..") != std::string::npos) return false;
    return true;
}

static bool mkdirParents(const std::string& filePath, mode_t mode) {
    size_t pos = 0;
    while (true) {
        pos = filePath.find('/', pos + 1);
        if (pos == std::string::npos) break;
        std::string partial = filePath.substr(0, pos);
        if (partial.empty()) continue;
        if (mkdir(partial.c_str(), mode) != 0 && errno != EEXIST) {
            return false;
        }
    }
    return true;
}

static size_t round512(size_t n) { return (n + 511) & ~size_t(511); }

static bool extractUstar(const std::vector<uint8_t>& tar, const std::string& destDir,
                         std::string* error) {
    size_t off = 0;
    std::string longName;
    int chownFailures = 0;

    while (off + 512 <= tar.size()) {
        const uint8_t* h = tar.data() + off;
        if (isZeroBlock(h)) {
            break;
        }

        const char* hdr = reinterpret_cast<const char*>(h);
        char typeflag = hdr[156];

        std::string name;
        if (typeflag == 'L') {
            size_t sz = parseOctalField(hdr + 124, 12);
            off += 512;
            if (off + round512(sz) > tar.size()) {
                setErr(error, "truncated tar (GNU longname)");
                return false;
            }
            longName.assign(reinterpret_cast<const char*>(tar.data() + off), sz);
            while (!longName.empty() && longName.back() == '\0') longName.pop_back();
            while (!longName.empty() && longName.back() == '\n') longName.pop_back();
            off += round512(sz);
            continue;
        }

        if (longName.empty()) {
            char namebuf[101];
            memcpy(namebuf, hdr, 100);
            namebuf[100] = '\0';
            size_t nlen = strnlen(namebuf, 100);
            name.assign(namebuf, nlen);

            char prefixbuf[156];
            memcpy(prefixbuf, hdr + 345, 155);
            prefixbuf[155] = '\0';
            size_t plen = strnlen(prefixbuf, 155);
            if (plen > 0) {
                name = std::string(prefixbuf, plen) + "/" + name;
            }
        } else {
            name = longName;
            longName.clear();
        }

        size_t size = parseOctalField(hdr + 124, 12);
        mode_t mode = static_cast<mode_t>(parseOctalField(hdr + 100, 8)) & 07777;
        uint32_t uid = parseId(hdr + 108);
        uint32_t gid = parseId(hdr + 116);

        off += 512;
        if (off + round512(size) > tar.size() && size > 0) {
            setErr(error, "truncated tar payload");
            return false;
        }

        const uint8_t* payload = tar.data() + off;

        if (!pathSafe(name)) {
            setErr(error, "unsafe tar path: " + name);
            return false;
        }

        std::string full = destDir + "/" + name;

        if (typeflag == '0' || typeflag == '\0') {
            if (!mkdirParents(full, 0755)) {
                setErr(error, std::string("mkdirParents: ") + strerror(errno));
                return false;
            }
            int fd = open(full.c_str(), O_WRONLY | O_CREAT | O_TRUNC, mode ? mode : 0644);
            if (fd < 0) {
                setErr(error, std::string("open ") + full + ": " + strerror(errno));
                return false;
            }
            const uint8_t* p = payload;
            size_t left = size;
            while (left > 0) {
                ssize_t w = write(fd, p, left);
                if (w <= 0) {
                    close(fd);
                    setErr(error, std::string("write ") + full + ": " + strerror(errno));
                    return false;
                }
                p += static_cast<size_t>(w);
                left -= static_cast<size_t>(w);
            }
            close(fd);
            applyOwner(full, uid, gid, &chownFailures);
            if (mode != 0) {
                chmod(full.c_str(), mode);
            }
        } else if (typeflag == '5') {
            if (!mkdirParents(full, 0755)) {
                setErr(error, std::string("mkdirParents (dir): ") + strerror(errno));
                return false;
            }
            if (mkdir(full.c_str(), mode ? mode : 0755) != 0 && errno != EEXIST) {
                setErr(error, std::string("mkdir ") + full + ": " + strerror(errno));
                return false;
            }
            applyOwner(full, uid, gid, &chownFailures);
            if (mode != 0) {
                chmod(full.c_str(), mode);
            }
        } else if (typeflag == '2') {
            // ustar: link target is in header linkname (157..256), not in the data block.
            // size is usually 0; some archives put the target only in the payload.
            char linkbuf[101];
            memcpy(linkbuf, hdr + 157, 100);
            linkbuf[100] = '\0';
            std::string target(linkbuf, strnlen(linkbuf, 100));
            if (target.empty() && size > 0) {
                target.assign(reinterpret_cast<const char*>(payload), size);
                while (!target.empty() && target.back() == '\0') target.pop_back();
                while (!target.empty() && target.back() == '\n') target.pop_back();
            }
            if (target.empty()) {
                setErr(error, std::string("empty symlink target: ") + name);
                return false;
            }
            if (!mkdirParents(full, 0755)) {
                setErr(error, std::string("mkdirParents (symlink): ") + strerror(errno));
                return false;
            }
            unlink(full.c_str());
            if (symlink(target.c_str(), full.c_str()) != 0) {
                setErr(error, std::string("symlink ") + full + " -> " + target + ": " +
                              strerror(errno));
                return false;
            }
            applyOwner(full, uid, gid, &chownFailures);
        } else {
            LOG(WARNING) << "skipping tar entry type " << typeflag << " " << name;
        }

        off += round512(size);
    }

    if (chownFailures > 0) {
        LOG(WARNING) << chownFailures << " tar entries could not be given their owner and stay root-owned";
    }
    return true;
}

}  // namespace

bool extractTarGz(const std::string& gzPath, const std::string& destDir, std::string* error) {
    int fd = open(gzPath.c_str(), O_RDONLY | O_CLOEXEC);
    if (fd < 0) {
        setErr(error, std::string("open template: ") + strerror(errno));
        return false;
    }

    std::vector<uint8_t> compressed;
    if (!readAllFd(fd, &compressed)) {
        close(fd);
        setErr(error, std::string("read template: ") + strerror(errno));
        return false;
    }
    close(fd);

    std::vector<uint8_t> tar;
    if (!gunzipInMemory(compressed, &tar, error)) {
        return false;
    }

    if (mkdir(destDir.c_str(), 0755) != 0 && errno != EEXIST) {
        setErr(error, std::string("mkdir dest: ") + strerror(errno));
        return false;
    }

    if (!extractUstar(tar, destDir, error)) {
        return false;
    }

    return true;
}

}  // namespace aohp

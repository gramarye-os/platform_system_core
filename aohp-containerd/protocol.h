/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#pragma once

#include <string>
#include <vector>
#include <sstream>

namespace aohp {

// Command opcodes sent from Java AohpContainerService over LocalSocket.
// Wire format: "<OPCODE> <arg1> <arg2> ...\n"
// Response:    "OK <json-or-text>\n"  or  "ERR <message>\n"
// For openShell, after "OK", the socket becomes a bidirectional PTY relay.

constexpr const char* CMD_LIST       = "LIST";
constexpr const char* CMD_CREATE     = "CREATE";     // CREATE <name> <template>
constexpr const char* CMD_DESTROY    = "DESTROY";    // DESTROY <name>
constexpr const char* CMD_RESET      = "RESET";      // RESET <name>
constexpr const char* CMD_EXEC       = "EXEC";       // EXEC <name> <timeout_ms> <command...>
constexpr const char* CMD_SHELL      = "SHELL";      // SHELL <name>

constexpr const char* RESP_OK  = "OK";
constexpr const char* RESP_ERR = "ERR";

constexpr const char* CONTAINER_BASE_DIR = "/data/aohp/envs";
constexpr const char* TEMPLATE_DIR       = "/system/etc/aohp/rootfs-templates";
constexpr const char* SHARED_BASE           = "/data/aohp/shared";
constexpr const char* SHARED_NPM_CACHE      = "/data/aohp/shared/npm-cache";
constexpr const char* SHARED_OPENCLAW_DEV   = "/data/aohp/shared/openclaw-dev";
constexpr const char* SHARED_UDA            = "/data/aohp/shared/uda";
constexpr const char* AOHP_CGROUP_CONF      = "/system/etc/aohp/cgroup.conf";

constexpr const char* CMD_TEMPLATE_INFO = "TEMPLATE_INFO";
constexpr const char* CMD_START_SVC     = "START_SVC";
constexpr const char* CMD_STOP_SVC      = "STOP_SVC";
constexpr const char* CMD_LIST_SVC      = "LIST_SVC";
constexpr const char* CMD_SVC_LOG       = "SVC_LOG";
constexpr const char* CMD_USAGE         = "USAGE";
constexpr const char* CMD_DIAG          = "DIAG";
constexpr const char* CMD_POWER         = "POWER";      // POWER [performance|saver] -> OK {"mode":...}
// UNIT <env> <op> [<base64 json>]: systemd-subset unit ops (unit_manager.h); OK <json> | ERR <msg>
constexpr const char* CMD_UNIT          = "UNIT";
constexpr const char* CMD_WHICHENV      = "WHICHENV";   // WHICHENV <pid> -> OK {"env":"<name>"} | ERR not in an env

inline std::vector<std::string> splitLine(const std::string& line) {
    std::vector<std::string> tokens;
    std::istringstream iss(line);
    std::string tok;
    while (iss >> tok) {
        tokens.push_back(tok);
    }
    return tokens;
}

inline std::string restOfLine(const std::string& line, size_t skipTokens) {
    size_t pos = 0;
    for (size_t i = 0; i < skipTokens && pos < line.size(); ++i) {
        while (pos < line.size() && line[pos] == ' ') ++pos;
        while (pos < line.size() && line[pos] != ' ') ++pos;
    }
    while (pos < line.size() && line[pos] == ' ') ++pos;
    return line.substr(pos);
}

}  // namespace aohp

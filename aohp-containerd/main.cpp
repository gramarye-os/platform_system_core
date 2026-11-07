/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#define LOG_TAG "aohp-containerd"

#include "container_manager.h"
#include "protocol.h"
#include "session.h"
#include "unit_file.h"
#include "unit_manager.h"

#include <cerrno>
#include <csignal>
#include <cstdlib>
#include <cstring>
#include <string>
#include <thread>

#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#include <unistd.h>

#include <android-base/logging.h>
#include <cutils/sockets.h>

using namespace aohp;

// Constructed in main() after the --client check so the debug client does not initialise cgroups/logging.
static ContainerManager* gMgrPtr = nullptr;
#define gMgr (*gMgrPtr)

static std::string toJson(const ExecResult& r) {
    auto escape = [](const std::string& s) -> std::string {
        std::string out;
        out.reserve(s.size());
        for (char c : s) {
            switch (c) {
                case '\\':
                    out += "\\\\";
                    break;
                case '"':
                    out += "\\\"";
                    break;
                case '\n':
                    out += "\\n";
                    break;
                case '\r':
                    out += "\\r";
                    break;
                case '\t':
                    out += "\\t";
                    break;
                default:
                    out += c;
                    break;
            }
        }
        return out;
    };
    return "{\"exitCode\":" + std::to_string(r.exitCode) + ",\"stdout\":\"" + escape(r.stdoutStr) +
           "\",\"stderr\":\"" + escape(r.stderrStr) + "\"}";
}

static std::string base64Encode(const std::string& in) {
    static const char kB64[] =
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    int val = 0;
    int valb = -6;
    for (unsigned char c : in) {
        val = (val << 8) + c;
        valb += 8;
        while (valb >= 0) {
            out.push_back(kB64[(val >> valb) & 0x3F]);
            valb -= 6;
        }
    }
    if (valb > -6) {
        out.push_back(kB64[((val << 8) >> (valb + 8)) & 0x3F]);
    }
    while (out.size() % 4) {
        out.push_back('=');
    }
    return out;
}

static void handleClient(int clientFd) {
    FILE* fp = fdopen(dup(clientFd), "r");
    if (!fp) {
        close(clientFd);
        return;
    }

    char lineBuf[8192];
    while (fgets(lineBuf, sizeof(lineBuf), fp)) {
        std::string line(lineBuf);
        while (!line.empty() && (line.back() == '\n' || line.back() == '\r')) {
            line.pop_back();
        }
        if (line.empty()) continue;

        auto tokens = splitLine(line);
        if (tokens.empty()) continue;

        std::string response;
        const std::string& cmd = tokens[0];

        if (cmd == CMD_LIST) {
            auto list = gMgr.listContainers();
            std::string joined;
            for (size_t i = 0; i < list.size(); ++i) {
                if (i > 0) joined += ",";
                joined += list[i];
            }
            response = std::string(RESP_OK) + " " + joined + "\n";

        } else if (cmd == CMD_CREATE && tokens.size() >= 3) {
            bool ok = gMgr.createContainer(tokens[1], tokens[2]);
            if (ok) {
                response = std::string(RESP_OK) + " created\n";
            } else {
                std::string detail = gMgr.getLastError();
                if (detail.empty()) detail = "create failed";
                for (char& c : detail) {
                    if (c == '\n' || c == '\r') c = ' ';
                }
                response = std::string(RESP_ERR) + " " + detail + "\n";
            }

        } else if (cmd == CMD_DESTROY && tokens.size() >= 2) {
            bool ok = gMgr.destroyContainer(tokens[1]);
            if (ok) {
                response = std::string(RESP_OK) + " destroyed\n";
            } else {
                std::string detail = gMgr.getLastError();
                for (char& c : detail) {
                    if (c == '\n' || c == '\r') c = ' ';
                }
                if (detail.empty()) detail = "destroy failed";
                response = std::string(RESP_ERR) + " " + detail + "\n";
            }

        } else if (cmd == CMD_RESET && tokens.size() >= 2) {
            bool ok = gMgr.resetContainer(tokens[1]);
            response = ok ? std::string(RESP_OK) + " reset\n"
                          : std::string(RESP_ERR) + " reset failed\n";

        } else if (cmd == CMD_EXEC && tokens.size() >= 4) {
            std::string name = tokens[1];
            int timeout = atoi(tokens[2].c_str());
            std::string command = restOfLine(line, 3);
            auto result = gMgr.execSync(name, command, timeout);
            response = std::string(RESP_OK) + " " + toJson(result) + "\n";

        } else if (cmd == CMD_SHELL && tokens.size() >= 2) {
            std::string name = tokens[1];
            int masterFd = gMgr.openShell(name);
            if (masterFd < 0) {
                response = std::string(RESP_ERR) + " shell failed\n";
            } else {
                std::string ok = std::string(RESP_OK) + " shell\n";
                write(clientFd, ok.c_str(), ok.size());
                fclose(fp);
                relayPtyToSocket(masterFd, clientFd);
                close(clientFd);
                return;
            }

        } else if (cmd == CMD_TEMPLATE_INFO && tokens.size() >= 2) {
            std::string info = gMgr.templateInfo(tokens[1]);
            response = std::string(RESP_OK) + " " + info + "\n";

        } else if (cmd == CMD_START_SVC && tokens.size() >= 4) {
            std::string name = tokens[1];
            std::string sid = tokens[2];
            std::string svcCmd = restOfLine(line, 3);
            long pid = gMgr.startService(name, sid, svcCmd);
            if (pid < 0) {
                std::string detail = gMgr.getLastError();
                if (detail.empty()) detail = "startService failed";
                response = std::string(RESP_ERR) + " " + detail + "\n";
            } else {
                response = std::string(RESP_OK) + " " + std::to_string(pid) + "\n";
            }

        } else if (cmd == CMD_STOP_SVC && tokens.size() >= 3) {
            bool ok = gMgr.stopService(tokens[1], tokens[2]);
            response = ok ? std::string(RESP_OK) + " stopped\n"
                          : std::string(RESP_ERR) + " stop failed\n";

        } else if (cmd == CMD_LIST_SVC && tokens.size() >= 2) {
            std::string js = gMgr.listServicesJson(tokens[1]);
            response = std::string(RESP_OK) + " " + js + "\n";

        } else if (cmd == CMD_SVC_LOG && tokens.size() >= 4) {
            int tail = atoi(tokens[3].c_str());
            std::string raw = gMgr.serviceLogTail(tokens[1], tokens[2], tail);
            response = std::string(RESP_OK) + " " + base64Encode(raw) + "\n";

        } else if (cmd == CMD_USAGE && tokens.size() >= 2) {
            std::string js = gMgr.getUsageJson(tokens[1]);
            response = std::string(RESP_OK) + " " + js + "\n";

        } else if (cmd == CMD_DIAG && tokens.size() >= 2) {
            std::string js = gMgr.diagnose(tokens[1]);
            response = std::string(RESP_OK) + " " + js + "\n";

        } else if (cmd == CMD_POWER) {
            // POWER [performance|saver]  ->  OK {"mode":...}  Which cpuset env processes run in; setting it
            // moves every live process of every container (the daemon itself stays in system-background).
            auto& cg = gMgr.cgroup();
            if (tokens.size() >= 2) {
                CgroupController::PowerMode pm;
                if (!CgroupController::parsePowerMode(tokens[1], &pm)) {
                    response = std::string(RESP_ERR) + " unknown power mode\n";
                } else {
                    cg.setPowerMode(pm);
                    cg.applyCpusetToAll();
                    for (const auto& name : gMgr.listContainers()) cg.applyCpusetToContainer(name);
                }
            }
            if (response.empty()) {
                response = std::string(RESP_OK) + " {\"mode\":\"" + CgroupController::powerModeName(cg.powerMode()) + "\"}\n";
            }

        } else if (cmd == CMD_WHICHENV && tokens.size() >= 2) {
            // WHICHENV <pid>  ->  OK {"env":"<name>"} | ERR not in an env
            char* endp = nullptr;
            long pid = strtol(tokens[1].c_str(), &endp, 10);
            std::string env = (endp && *endp == '\0' && pid > 1) ? gMgr.envOfPid(static_cast<pid_t>(pid)) : "";
            response = env.empty() ? std::string(RESP_ERR) + " not in an env\n"
                                   : std::string(RESP_OK) + " {\"env\":\"" + env + "\"}\n";

        } else if (cmd == CMD_UNIT && tokens.size() >= 3) {
            // UNIT <env> <op> [<base64 json args>]  ->  OK <json> | ERR <message>
            std::string args = tokens.size() >= 4 ? base64Decode(tokens[3]) : "{}";
            std::string out, err;
            if (gMgr.units().op(tokens[1], tokens[2], args, &out, &err)) {
                response = std::string(RESP_OK) + " " + out + "\n";
            } else {
                for (char& c : err) {
                    if (c == '\n' || c == '\r') c = ' ';
                }
                response = std::string(RESP_ERR) + " " + err + "\n";
            }

        } else {
            response = std::string(RESP_ERR) + " unknown command\n";
        }

        write(clientFd, response.c_str(), response.size());
    }

    fclose(fp);
    close(clientFd);
}

// Debug client: aohp-containerd --client '<LINE>' [--socket PATH]
// Sends one protocol line to the daemon socket and prints the single-line response (root only:
// the init socket is 0660 system). Lets the UNIT ops be exercised without the framework.
static int runClient(const std::string& line, const std::string& sockPath) {
    int fd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
    if (fd < 0) {
        perror("socket");
        return 2;
    }
    struct sockaddr_un addr;
    memset(&addr, 0, sizeof(addr));
    addr.sun_family = AF_UNIX;
    strncpy(addr.sun_path, sockPath.c_str(), sizeof(addr.sun_path) - 1);
    if (connect(fd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
        perror(("connect " + sockPath).c_str());
        close(fd);
        return 2;
    }
    std::string msg = line + "\n";
    if (write(fd, msg.c_str(), msg.size()) != static_cast<ssize_t>(msg.size())) {
        perror("write");
        close(fd);
        return 2;
    }
    std::string resp;
    char buf[65536];
    ssize_t n;
    while ((n = read(fd, buf, sizeof(buf))) > 0) {
        resp.append(buf, n);
        if (resp.find('\n') != std::string::npos) break;
    }
    close(fd);
    fputs(resp.c_str(), stdout);
    if (resp.empty() || resp.back() != '\n') fputs("\n", stdout);
    return resp.compare(0, 2, "OK") == 0 ? 0 : 1;
}

int main(int argc, char** argv) {
    // A response written to a control socket the client has already closed (e.g. a multi-line EXEC
    // command parsed as several requests) must not kill the daemon - and with it every env.
    signal(SIGPIPE, SIG_IGN);
    std::string clientLine, sockPath = "/dev/socket/aohp_container", bindPath;
    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        if (a == "--client" && i + 1 < argc) clientLine = argv[++i];
        else if (a == "--socket" && i + 1 < argc) sockPath = argv[++i];
        else if (a == "--bind" && i + 1 < argc) bindPath = argv[++i];
        else if (a == "--help" || a == "-h") {
            fputs("usage: aohp-containerd [--bind PATH]            (daemon; init passes the socket)\n"
                  "       aohp-containerd --client LINE [--socket PATH]\n", stdout);
            return 0;
        }
    }
    if (!clientLine.empty()) return runClient(clientLine, sockPath);

    android::base::InitLogging(argv, android::base::LogdLogger(android::base::SYSTEM));
    LOG(INFO) << "aohp-containerd starting";
    gMgrPtr = new ContainerManager();

    mkdir("/data/aohp", 0770);
    mkdir(CONTAINER_BASE_DIR, 0770);
    mkdir(SHARED_BASE, 0770);
    mkdir(SHARED_NPM_CACHE, 0770);
    mkdir(SHARED_OPENCLAW_DEV, 0770);

    gMgr.adoptOrphanServicePids();

    gMgr.units().start();

    int serverFd = android_get_control_socket("aohp_container");
    if (serverFd < 0 && !bindPath.empty()) {
        // Test/debug deployment without init: bind a plain unix socket ourselves.
        serverFd = socket(AF_UNIX, SOCK_STREAM | SOCK_CLOEXEC, 0);
        struct sockaddr_un addr;
        memset(&addr, 0, sizeof(addr));
        addr.sun_family = AF_UNIX;
        strncpy(addr.sun_path, bindPath.c_str(), sizeof(addr.sun_path) - 1);
        unlink(bindPath.c_str());
        if (serverFd < 0 || bind(serverFd, reinterpret_cast<struct sockaddr*>(&addr), sizeof(addr)) != 0) {
            PLOG(FATAL) << "bind " << bindPath;
            return 1;
        }
        chmod(bindPath.c_str(), 0660);
        LOG(INFO) << "listening on " << bindPath << " (--bind)";
    }
    if (serverFd < 0) {
        PLOG(FATAL) << "Failed to get control socket 'aohp_container'";
        return 1;
    }

    if (listen(serverFd, 8) < 0) {
        PLOG(FATAL) << "listen";
        return 1;
    }

    LOG(INFO) << "aohp-containerd listening on control socket";

    while (true) {
        struct sockaddr_un addr;
        socklen_t addrLen = sizeof(addr);
        int clientFd = accept(serverFd, reinterpret_cast<struct sockaddr*>(&addr), &addrLen);
        if (clientFd < 0) {
            if (errno == EINTR) continue;
            PLOG(ERROR) << "accept";
            continue;
        }

        std::thread(handleClient, clientFd).detach();
    }

    return 0;
}

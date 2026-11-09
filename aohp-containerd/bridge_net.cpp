/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#include "bridge_net.h"

#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <linux/if_link.h>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <net/if.h>
#include <poll.h>
#include <sys/socket.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <thread>

#include <android-base/logging.h>

namespace aohp {

namespace {

constexpr const char* kNdc = "/system/bin/ndc";
constexpr const char* kIptables = "/system/bin/iptables";
// netd's own name for the host's local-network routing table (RouteController).
constexpr const char* kLocalNetwork = "local";
// Tag netd records our forwarding requester under (ndc ipfwd enable/disable <requester>).
constexpr const char* kFwdRequester = "aohp";
// netd never flushes the OEM chains; they are traversed first in FORWARD, and ACCEPT there
// ends the table before tetherctrl_FORWARD's final DROP.
constexpr const char* kOemFwdChain = "oem_fwd";
constexpr int kRouteSettleMs = 1500;

// Walk the attributes of a netlink message into a map (first occurrence wins).
std::map<int, const rtattr*> parseAttrs(const rtattr* rta, int len) {
    std::map<int, const rtattr*> m;
    for (; RTA_OK(rta, len); rta = RTA_NEXT(rta, len)) {
        m.emplace(rta->rta_type & NLA_TYPE_MASK, rta);
    }
    return m;
}

std::string attrString(const rtattr* a) {
    if (!a) return "";
    const char* s = static_cast<const char*>(RTA_DATA(a));
    return std::string(s, strnlen(s, RTA_PAYLOAD(a)));
}

}  // namespace

bool BridgeNetManager::start() {
    int sock = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (sock < 0) {
        PLOG(ERROR) << "bridge-net: netlink socket";
        return false;
    }
    sockaddr_nl sa = {};
    sa.nl_family = AF_NETLINK;
    sa.nl_groups = RTMGRP_LINK | RTMGRP_IPV4_IFADDR | RTMGRP_IPV4_ROUTE;
    if (bind(sock, reinterpret_cast<sockaddr*>(&sa), sizeof(sa)) != 0) {
        PLOG(ERROR) << "bridge-net: bind netlink groups";
        close(sock);
        return false;
    }
    std::thread([this, sock] { run(sock); }).detach();
    return true;
}

// Dump the current links and addresses so a bridge that already exists (daemon restart while
// containers run) is registered too. Dumps arrive on the monitor socket; handleMessage sorts them.
bool BridgeNetManager::dumpLinksAndAddrs(int sock) {
    struct {
        nlmsghdr nh;
        rtgenmsg g;
    } req = {};
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(rtgenmsg));
    req.nh.nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    req.g.rtgen_family = AF_UNSPEC;
    for (int type : {RTM_GETLINK, RTM_GETADDR}) {
        req.nh.nlmsg_type = type;
        req.nh.nlmsg_seq = type;
        if (type == RTM_GETADDR) req.g.rtgen_family = AF_INET;
        if (send(sock, &req, req.nh.nlmsg_len, 0) < 0) {
            PLOG(WARNING) << "bridge-net: netlink dump request " << type;
            return false;
        }
        // Consume this dump up to NLMSG_DONE before issuing the next, so the kernel does not
        // reject the second request with EBUSY.
        char buf[32768];
        bool done = false;
        while (!done) {
            ssize_t n = recv(sock, buf, sizeof(buf), 0);
            if (n < 0) {
                if (errno == EINTR) continue;
                PLOG(WARNING) << "bridge-net: netlink dump recv";
                return false;
            }
            for (const nlmsghdr* nh = reinterpret_cast<nlmsghdr*>(buf); NLMSG_OK(nh, n);
                 nh = NLMSG_NEXT(nh, n)) {
                if (nh->nlmsg_type == NLMSG_DONE) {
                    done = true;
                    break;
                }
                if (nh->nlmsg_type == NLMSG_ERROR) {
                    done = true;
                    break;
                }
                handleMessage(nh);
            }
        }
    }
    return true;
}

void BridgeNetManager::run(int sock) {
    dumpLinksAndAddrs(sock);
    char buf[32768];
    bool routesDirty = false;
    for (;;) {
        pollfd pfd = {sock, POLLIN, 0};
        int rc = poll(&pfd, 1, routesDirty ? kRouteSettleMs : -1);
        if (rc == 0) {
            routesDirty = false;
            rebindUpstreams();
            continue;
        }
        if (rc < 0) {
            if (errno == EINTR) continue;
            PLOG(ERROR) << "bridge-net: poll";
            sleep(1);
            continue;
        }
        ssize_t n = recv(sock, buf, sizeof(buf), 0);
        if (n < 0) {
            if (errno == EINTR) continue;
            if (errno == ENOBUFS) {
                // Missed events; resync from a fresh dump.
                LOG(WARNING) << "bridge-net: netlink overrun, resyncing";
                dumpLinksAndAddrs(sock);
                routesDirty = true;
                continue;
            }
            PLOG(ERROR) << "bridge-net: recv";
            sleep(1);
            continue;
        }
        for (const nlmsghdr* nh = reinterpret_cast<nlmsghdr*>(buf); NLMSG_OK(nh, n);
             nh = NLMSG_NEXT(nh, n)) {
            if (nh->nlmsg_type == RTM_NEWROUTE || nh->nlmsg_type == RTM_DELROUTE) {
                if (!bridges_.empty()) routesDirty = true;
                continue;
            }
            handleMessage(nh);
        }
    }
}

void BridgeNetManager::handleMessage(const nlmsghdr* nh) {
    switch (nh->nlmsg_type) {
        case RTM_NEWLINK: onLink(nh, false); break;
        case RTM_DELLINK: onLink(nh, true); break;
        case RTM_NEWADDR: onAddr(nh, false); break;
        case RTM_DELADDR: onAddr(nh, true); break;
        default: break;
    }
}

void BridgeNetManager::onLink(const nlmsghdr* nh, bool gone) {
    const ifinfomsg* ifi = static_cast<const ifinfomsg*>(NLMSG_DATA(nh));
    int len = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifi));
    if (len < 0) return;
    auto attrs = parseAttrs(IFLA_RTA(ifi), len);
    std::string name = attrString(attrs.count(IFLA_IFNAME) ? attrs[IFLA_IFNAME] : nullptr);
    if (gone) {
        auto it = bridges_.find(ifi->ifi_index);
        if (it != bridges_.end()) {
            unregisterBridge(it->second, /*linkGone=*/true);
            bridges_.erase(it);
        }
        kind_.erase(ifi->ifi_index);
        name_.erase(ifi->ifi_index);
        return;
    }
    if (!name.empty()) name_[ifi->ifi_index] = name;
    if (attrs.count(IFLA_LINKINFO)) {
        const rtattr* li = attrs[IFLA_LINKINFO];
        auto info = parseAttrs(static_cast<const rtattr*>(RTA_DATA(li)), RTA_PAYLOAD(li));
        if (info.count(IFLA_INFO_KIND)) kind_[ifi->ifi_index] = attrString(info[IFLA_INFO_KIND]);
    }
}

void BridgeNetManager::onAddr(const nlmsghdr* nh, bool gone) {
    const ifaddrmsg* ifa = static_cast<const ifaddrmsg*>(NLMSG_DATA(nh));
    if (ifa->ifa_family != AF_INET) return;
    int len = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*ifa));
    if (len < 0) return;
    auto kit = kind_.find(ifa->ifa_index);
    if (kit == kind_.end() || kit->second != "bridge") return;
    auto attrs = parseAttrs(IFA_RTA(ifa), len);
    const rtattr* a = attrs.count(IFA_LOCAL) ? attrs[IFA_LOCAL]
                      : attrs.count(IFA_ADDRESS) ? attrs[IFA_ADDRESS] : nullptr;
    if (!a || RTA_PAYLOAD(a) < 4) return;
    uint32_t addr;
    memcpy(&addr, RTA_DATA(a), 4);
    uint32_t mask = ifa->ifa_prefixlen == 0 ? 0 : htonl(~uint32_t(0) << (32 - ifa->ifa_prefixlen));
    in_addr net = {addr & mask};
    char txt[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &net, txt, sizeof(txt));
    std::string subnet = std::string(txt) + "/" + std::to_string(ifa->ifa_prefixlen);
    std::string ifname = name_.count(ifa->ifa_index) ? name_[ifa->ifa_index] : "";
    if (ifname.empty()) {
        char nb[IF_NAMESIZE];
        if (if_indextoname(ifa->ifa_index, nb)) ifname = nb;
    }
    if (ifname.empty()) return;

    auto it = bridges_.find(ifa->ifa_index);
    if (gone) {
        if (it != bridges_.end() && it->second.subnet == subnet) {
            unregisterBridge(it->second, /*linkGone=*/false);
            bridges_.erase(it);
        }
        return;
    }
    if (it != bridges_.end()) {
        if (it->second.subnet == subnet && it->second.registered) return;
        unregisterBridge(it->second, /*linkGone=*/false);
        bridges_.erase(it);
    }
    Bridge b;
    b.ifname = ifname;
    b.subnet = subnet;
    registerBridge(b);
    bridges_[ifa->ifa_index] = b;
}

void BridgeNetManager::registerBridge(Bridge& b) {
    LOG(INFO) << "bridge-net: registering " << b.ifname << " " << b.subnet;
    const char* ifn = b.ifname.c_str();
    const char* subnet = b.subnet.c_str();
    // Rules 11000/17000 (local_network for oif), route in the local table: host <-> bridge
    // reachability, and forwarded packets pass source validation (they were martians before).
    ndc({"network", "interface", "add", kLocalNetwork, ifn}, /*quiet=*/true);
    ndc({"network", "route", "add", kLocalNetwork, ifn, subnet});
    if (!ipfwdEnabled_) {
        ndc({"ipfwd", "enable", kFwdRequester});
        ipfwdEnabled_ = true;
    }
    b.upstream = upstreamIface();
    if (!b.upstream.empty()) {
        // tetherctrl_FORWARD accept pair + rule 21000 "iif <bridge> lookup <uplink table>" +
        // MASQUERADE on the uplink: egress from the bridge.
        ndc({"ipfwd", "add", ifn, b.upstream.c_str()});
        ndc({"nat", "enable", ifn, b.upstream.c_str(), "0"});
    } else {
        LOG(INFO) << "bridge-net: no uplink yet for " << b.ifname << "; egress bound on route change";
    }
    // Same-bridge forwarding (container <-> container; the bridge has hairpin off so this is
    // routed through the host) and inbound DNAT for published ports. -C first: idempotent.
    if (runCmd({kIptables, "-C", kOemFwdChain, "-i", ifn, "-o", ifn, "-j", "ACCEPT"}, true) != 0)
        iptables({"-A", kOemFwdChain, "-i", ifn, "-o", ifn, "-j", "ACCEPT"});
    if (runCmd({kIptables, "-C", kOemFwdChain, "-o", ifn, "-m", "conntrack", "--ctstate", "DNAT",
                "-j", "ACCEPT"}, true) != 0)
        iptables({"-A", kOemFwdChain, "-o", ifn, "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"});
    b.registered = true;
}

void BridgeNetManager::unregisterBridge(Bridge& b, bool linkGone) {
    if (!b.registered) return;
    LOG(INFO) << "bridge-net: unregistering " << b.ifname << " " << b.subnet
              << (linkGone ? " (link gone)" : "");
    const char* ifn = b.ifname.c_str();
    iptables({"-D", kOemFwdChain, "-i", ifn, "-o", ifn, "-j", "ACCEPT"});
    iptables({"-D", kOemFwdChain, "-o", ifn, "-m", "conntrack", "--ctstate", "DNAT", "-j", "ACCEPT"});
    if (!b.upstream.empty()) {
        ndc({"nat", "disable", ifn, b.upstream.c_str(), "0"}, linkGone);
        ndc({"ipfwd", "remove", ifn, b.upstream.c_str()}, linkGone);
    }
    // With the link gone the kernel already dropped the route and the rules; netd still holds
    // the interface in its local network record, so the remove is what keeps the next
    // "interface add" for a recreated bridge clean.
    ndc({"network", "route", "remove", kLocalNetwork, ifn, b.subnet.c_str()}, linkGone);
    ndc({"network", "interface", "remove", kLocalNetwork, ifn}, linkGone);
    b.registered = false;
    bool others = false;
    for (const auto& kv : bridges_) {
        if (kv.second.registered && kv.second.ifname != b.ifname) others = true;
    }
    if (!others && ipfwdEnabled_) {
        ndc({"ipfwd", "disable", kFwdRequester});
        ipfwdEnabled_ = false;
    }
}

// Default network changed (wlan <-> rmnet, Wi-Fi off/on): re-point ipfwd/nat for every bridge.
void BridgeNetManager::rebindUpstreams() {
    if (bridges_.empty()) return;
    std::string up = upstreamIface();
    for (auto& kv : bridges_) {
        Bridge& b = kv.second;
        if (!b.registered || b.upstream == up) continue;
        LOG(INFO) << "bridge-net: uplink for " << b.ifname << ": '" << b.upstream << "' -> '" << up << "'";
        if (!b.upstream.empty()) {
            ndc({"nat", "disable", b.ifname.c_str(), b.upstream.c_str(), "0"}, true);
            ndc({"ipfwd", "remove", b.ifname.c_str(), b.upstream.c_str()}, true);
        }
        b.upstream = up;
        if (!up.empty()) {
            ndc({"ipfwd", "add", b.ifname.c_str(), up.c_str()});
            ndc({"nat", "enable", b.ifname.c_str(), up.c_str(), "0"});
        }
    }
}

// The interface a packet to the Internet leaves on right now: RTM_GETROUTE for 8.8.8.8, which
// walks Android's policy rules the same way "ip route get" does (uid 0, no fwmark: default
// network). Empty when there is no default network.
std::string BridgeNetManager::upstreamIface() {
    int s = socket(AF_NETLINK, SOCK_RAW | SOCK_CLOEXEC, NETLINK_ROUTE);
    if (s < 0) return "";
    struct {
        nlmsghdr nh;
        rtmsg rt;
        char attrs[64];
    } req = {};
    req.nh.nlmsg_len = NLMSG_LENGTH(sizeof(rtmsg));
    req.nh.nlmsg_type = RTM_GETROUTE;
    req.nh.nlmsg_flags = NLM_F_REQUEST;
    req.nh.nlmsg_seq = 1;
    req.rt.rtm_family = AF_INET;
    req.rt.rtm_dst_len = 32;
    rtattr* rta = reinterpret_cast<rtattr*>(reinterpret_cast<char*>(&req) + NLMSG_ALIGN(req.nh.nlmsg_len));
    rta->rta_type = RTA_DST;
    rta->rta_len = RTA_LENGTH(4);
    in_addr dst;
    inet_pton(AF_INET, "8.8.8.8", &dst);
    memcpy(RTA_DATA(rta), &dst, 4);
    req.nh.nlmsg_len = NLMSG_ALIGN(req.nh.nlmsg_len) + RTA_ALIGN(rta->rta_len);
    std::string result;
    if (send(s, &req, req.nh.nlmsg_len, 0) >= 0) {
        char buf[8192];
        pollfd pfd = {s, POLLIN, 0};
        if (poll(&pfd, 1, 2000) > 0) {
            ssize_t n = recv(s, buf, sizeof(buf), 0);
            for (const nlmsghdr* nh = reinterpret_cast<nlmsghdr*>(buf); n > 0 && NLMSG_OK(nh, n);
                 nh = NLMSG_NEXT(nh, n)) {
                if (nh->nlmsg_type != RTM_NEWROUTE) continue;
                const rtmsg* rt = static_cast<const rtmsg*>(NLMSG_DATA(nh));
                int len = nh->nlmsg_len - NLMSG_LENGTH(sizeof(*rt));
                auto attrs = parseAttrs(RTM_RTA(rt), len);
                if (attrs.count(RTA_OIF)) {
                    int oif;
                    memcpy(&oif, RTA_DATA(attrs[RTA_OIF]), sizeof(oif));
                    char nb[IF_NAMESIZE];
                    if (if_indextoname(oif, nb)) result = nb;
                }
                break;
            }
        }
    }
    close(s);
    // Never treat a bridge or loopback as the uplink (no default network: 8.8.8.8 may resolve
    // to a bridge's connected route through the local table when a container subnet is odd).
    if (result == "lo" || result.rfind("podman", 0) == 0 || result.rfind("docker", 0) == 0 ||
        result.rfind("cni", 0) == 0 || result.rfind("br-", 0) == 0)
        result.clear();
    return result;
}

int BridgeNetManager::runCmd(const std::vector<std::string>& argv, bool quiet) {
    int out[2];
    if (pipe2(out, O_CLOEXEC) != 0) return -1;
    pid_t pid = fork();
    if (pid < 0) {
        close(out[0]);
        close(out[1]);
        return -1;
    }
    if (pid == 0) {
        dup2(out[1], STDOUT_FILENO);
        dup2(out[1], STDERR_FILENO);
        int devnull = open("/dev/null", O_RDONLY);
        if (devnull >= 0) dup2(devnull, STDIN_FILENO);
        std::vector<char*> av;
        for (const auto& a : argv) av.push_back(const_cast<char*>(a.c_str()));
        av.push_back(nullptr);
        execv(av[0], av.data());
        _exit(127);
    }
    close(out[1]);
    std::string output;
    char buf[1024];
    ssize_t n;
    while ((n = read(out[0], buf, sizeof(buf))) > 0) output.append(buf, n);
    close(out[0]);
    int status = 0;
    waitpid(pid, &status, 0);
    int rc = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    std::string cmd;
    for (const auto& a : argv) cmd += (cmd.empty() ? "" : " ") + a;
    while (!output.empty() && (output.back() == '\n' || output.back() == '\r')) output.pop_back();
    if (rc != 0 && !quiet) {
        LOG(WARNING) << "bridge-net: '" << cmd << "' rc=" << rc << ": " << output;
    } else {
        LOG(DEBUG) << "bridge-net: '" << cmd << "' rc=" << rc << ": " << output;
    }
    return rc;
}

void BridgeNetManager::ndc(std::initializer_list<const char*> args, bool quiet) {
    std::vector<std::string> argv{kNdc};
    for (const char* a : args) argv.push_back(a);
    runCmd(argv, quiet);
}

void BridgeNetManager::iptables(std::initializer_list<const char*> args) {
    std::vector<std::string> argv{kIptables};
    for (const char* a : args) argv.push_back(a);
    runCmd(argv, /*quiet=*/false);
}

}  // namespace aohp

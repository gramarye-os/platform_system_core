/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#pragma once

#include <linux/netlink.h>

#include <initializer_list>
#include <map>
#include <string>
#include <vector>

namespace aohp {

/**
 * Plumbs container bridges created inside an env (podman0, docker0, cni-*) into Android's
 * network stack. Envs share the host network namespace, so the kernel sees the bridge, but
 * Android's policy routing never consults the main table and netd's tetherctrl_FORWARD chain
 * drops every forwarded flow it did not set up: without this, nothing on a bridge can reach the
 * host or the uplink. A RTNETLINK monitor thread watches for IPv4 addresses on bridge links and
 * registers each one through netd the way tethering does (ndc: local-network interface + route,
 * ipfwd, nat), plus two filter rules in netd's OEM chain for same-bridge forwarding and inbound
 * DNAT (published ports). Uplink changes (wlan <-> rmnet) re-point ipfwd/nat; link removal
 * (netavark deletes the bridge with its last container) unregisters.
 */
class BridgeNetManager {
public:
    /** Spawns the monitor thread; returns false when the netlink socket cannot be set up. */
    bool start();

private:
    struct Bridge {
        std::string ifname;
        std::string subnet;    // a.b.c.d/len
        std::string upstream;  // uplink interface the ipfwd/nat pair was issued for; "" = none
        bool registered = false;
    };

    void run(int sock);
    void handleMessage(const struct nlmsghdr* nh);
    void onLink(const struct nlmsghdr* nh, bool gone);
    void onAddr(const struct nlmsghdr* nh, bool gone);
    void registerBridge(Bridge& b);
    void unregisterBridge(Bridge& b, bool linkGone);
    void rebindUpstreams();
    bool dumpLinksAndAddrs(int sock);

    static std::string upstreamIface();
    static int runCmd(const std::vector<std::string>& argv, bool quiet = false);
    static void ndc(std::initializer_list<const char*> args, bool quiet = false);
    static void iptables(std::initializer_list<const char*> args);

    std::map<int, std::string> kind_;   // ifindex -> IFLA_INFO_KIND ("bridge", "veth", ...)
    std::map<int, std::string> name_;   // ifindex -> ifname
    std::map<int, Bridge> bridges_;     // ifindex -> registered bridge
    bool ipfwdEnabled_ = false;
};

}  // namespace aohp

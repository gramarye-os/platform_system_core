/*
 * Copyright (C) 2026 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 */

#pragma once

#include <string>

namespace aohp {

/**
 * Extract a gzip-compressed POSIX ustar tar (Alpine minirootfs format) into destDir.
 * Does not execute /system/bin/tar (toybox probes /vendor and violates coredomain policy).
 * Each entry gets the numeric owner and group recorded in the tar, then its mode.
 *
 * @param error optional; set on failure
 * @return true on success
 */
bool extractTarGz(const std::string& gzPath, const std::string& destDir, std::string* error);

}  // namespace aohp

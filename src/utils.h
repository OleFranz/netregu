#pragma once

#include <windivert.h>
#include <algorithm>
#include <windows.h>
#include <cctype>
#include <string>

#include "throttle.h"
#include "config.h"
#include "block.h"

std::string pid_to_executable(const DWORD pid);
const char* ip_to_string(UINT32 address, bool is_ipv4);
const char* ipv4_to_string(UINT32 address);
const char* ipv6_to_string(UINT32 address);
void parse_and_apply_throttle_rule(const std::string& rule);
void parse_and_apply_block_rule(const std::string& rule);
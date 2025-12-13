#pragma once

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdlib>
#include <filesystem>
#include <iomanip>
#include <sstream>
#include <string>

inline std::string toLowerCopy(const std::string &input) {
    std::string lowered = input;
    std::transform(lowered.begin(), lowered.end(), lowered.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return lowered;
}

inline std::string timestampNow() {
    const auto now = std::chrono::system_clock::now();
    const auto time = std::chrono::system_clock::to_time_t(now);
    std::tm tmBuffer{};
#ifdef _WIN32
    localtime_s(&tmBuffer, &time);
#else
    localtime_r(&time, &tmBuffer);
#endif
    std::ostringstream oss;
    oss << std::put_time(&tmBuffer, "%Y-%m-%d %H:%M:%S");
    return oss.str();
}

inline std::string expandEnvironmentVariables(const std::string &path) {
    std::string expanded;
    expanded.reserve(path.size());
    for (size_t i = 0; i < path.size(); ++i) {
        if (path[i] == '%' && path.find('%', i + 1) != std::string::npos) {
            const auto end = path.find('%', i + 1);
            const auto var = path.substr(i + 1, end - i - 1);
            const char *value = std::getenv(var.c_str());
            if (value) {
                expanded += value;
            }
            i = end;
        } else {
            expanded += path[i];
        }
    }
    return expanded;
}

inline std::string normalizePath(const std::string &path) {
    std::string normalized = path;
    std::replace(normalized.begin(), normalized.end(), '\\', '/');
    return normalized;
}

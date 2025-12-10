#include "DiscordScanner.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ctime>

namespace fs = std::filesystem;

static std::string timestampNow() {
    auto tp = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return buffer;
}

DiscordScanner::DiscordScanner(Logger &logger, const Weights &weights) : logger(logger), weights(weights) {}

void DiscordScanner::loadKeywords(const std::string &keywordFile, const std::vector<std::string> &serverList) {
    std::ifstream file(keywordFile);
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) keywords.push_back(line);
    }
    servers = serverList;
}

void DiscordScanner::analyzeLine(const std::string &line, const std::string &source) {
    std::string lower = line;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
    for (const auto &kw : keywords) {
        std::string kwLower = kw;
        std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), [](unsigned char c) { return std::tolower(c); });
        if (lower.find(kwLower) != std::string::npos) {
            LogEntry entry;
            entry.type = "Discord ключевое слово";
            entry.source = source;
            entry.matchedValue = kw;
            entry.weight = weights.discordWeight;
            entry.details = line;
            entry.timestamp = timestampNow();
            logger.logDiscordEvent(entry);
        }
    }
    for (const auto &server : servers) {
        std::string serverLower = server;
        std::transform(serverLower.begin(), serverLower.end(), serverLower.begin(), [](unsigned char c) { return std::tolower(c); });
        if (lower.find(serverLower) != std::string::npos) {
            LogEntry entry;
            entry.type = "Discord сервер";
            entry.source = source;
            entry.matchedValue = server;
            entry.weight = weights.discordWeight;
            entry.details = line;
            entry.timestamp = timestampNow();
            logger.logDiscordEvent(entry);
        }
    }
}

void DiscordScanner::scan(const std::vector<std::string> &files) {
    for (const auto &path : files) {
        std::error_code ec;
        if (path.empty() || !fs::exists(path, ec)) continue;
        std::ifstream file(path);
        if (!file.is_open()) continue;
        std::string line;
        while (std::getline(file, line)) {
            analyzeLine(line, path);
        }
    }
}


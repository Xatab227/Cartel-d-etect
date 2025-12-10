#include "BrowserScanner.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <ctime>

namespace fs = std::filesystem;

static std::string nowTime() {
    auto tp = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return buffer;
}

BrowserScanner::BrowserScanner(Logger &logger, const Weights &weights) : logger(logger), weights(weights) {}

void BrowserScanner::loadKeywords(const std::string &keywordFile, const std::string &siteFile) {
    auto loadList = [](const std::string &path) {
        std::vector<std::string> items;
        std::ifstream file(path);
        std::string line;
        while (std::getline(file, line)) {
            if (!line.empty()) items.push_back(line);
        }
        return items;
    };
    keywords = loadList(keywordFile);
    sites = loadList(siteFile);
}

void BrowserScanner::analyzeLine(const std::string &line, const std::string &source) {
    std::string lower = line;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });

    for (const auto &kw : keywords) {
        std::string kwLower = kw;
        std::transform(kwLower.begin(), kwLower.end(), kwLower.begin(), [](unsigned char c) { return std::tolower(c); });
        if (lower.find(kwLower) != std::string::npos) {
            LogEntry entry;
            entry.type = "Ключевое слово";
            entry.source = source;
            entry.matchedValue = kw;
            entry.weight = weights.keywordWeight;
            entry.details = line;
            entry.timestamp = nowTime();
            logger.logBrowserEvent(entry);
        }
    }

    for (const auto &site : sites) {
        std::string siteLower = site;
        std::transform(siteLower.begin(), siteLower.end(), siteLower.begin(), [](unsigned char c) { return std::tolower(c); });
        if (lower.find(siteLower) != std::string::npos) {
            LogEntry entry;
            entry.type = "URL/домен";
            entry.source = source;
            entry.matchedValue = site;
            entry.weight = weights.siteWeight;
            entry.details = line;
            entry.timestamp = nowTime();
            logger.logBrowserEvent(entry);
        }
    }
}

void BrowserScanner::scan(const std::vector<std::string> &files) {
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


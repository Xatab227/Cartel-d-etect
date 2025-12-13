#include "BrowserScanner.h"
#include "Utility.h"

#include <filesystem>
#include <fstream>
#include <iostream>

BrowserScanner::BrowserScanner(const Config &config, Logger &logger) : config(config), logger(logger) {}

void BrowserScanner::processFile(const std::string &path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Не удалось открыть лог браузера: " << path << "\n";
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        const auto lowered = toLowerCopy(line);
        for (const auto &domain : config.domains) {
            if (lowered.find(toLowerCopy(domain)) != std::string::npos) {
                LogEntry log;
                log.category = "Браузер";
                log.triggerType = "Домен";
                log.source = path;
                log.matchedValue = domain;
                log.weight = config.weights.domainMatch;
                log.timestamp = timestampNow();
                logger.addEntry(log);
            }
        }
        for (const auto &keyword : config.keywords) {
            const auto keywordLower = toLowerCopy(keyword);
            if (lowered.find(keywordLower) != std::string::npos) {
                LogEntry log;
                log.category = "Браузер";
                log.triggerType = "Ключевое слово";
                log.source = path;
                log.matchedValue = keyword;
                log.weight = config.weights.keywordMatch;
                log.timestamp = timestampNow();
                logger.addEntry(log);
            }
        }
    }
}

void BrowserScanner::run() {
    for (const auto &path : config.browserLogFiles) {
        processFile(path);
    }
}

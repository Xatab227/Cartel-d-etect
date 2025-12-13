#include "DiscordScanner.h"
#include "Utility.h"

#include <fstream>
#include <iostream>
#include <vector>

namespace {
std::vector<std::string> loadTriggerWords(const std::string &path) {
    std::vector<std::string> words;
    std::ifstream file(path);
    if (!file.is_open()) {
        return words;
    }
    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty()) {
            words.push_back(line);
        }
    }
    return words;
}
} // namespace

DiscordScanner::DiscordScanner(const Config &config, Logger &logger)
    : config(config), logger(logger) {}

void DiscordScanner::processFile(const std::string &path) {
    const auto triggers = loadTriggerWords(config.triggerWordsPath);
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Не удалось открыть лог Discord: " << path << "\n";
        return;
    }

    std::string line;
    while (std::getline(file, line)) {
        const auto lowered = toLowerCopy(line);
        for (const auto &keyword : config.keywords) {
            const auto keywordLower = toLowerCopy(keyword);
            if (lowered.find(keywordLower) != std::string::npos) {
                LogEntry log;
                log.category = "Discord";
                log.triggerType = "Ключевое слово";
                log.source = path;
                log.matchedValue = keyword;
                log.weight = config.weights.discordMatch;
                log.timestamp = timestampNow();
                logger.addEntry(log);
            }
        }
        for (const auto &trigger : triggers) {
            const auto triggerLower = toLowerCopy(trigger);
            if (!triggerLower.empty() && lowered.find(triggerLower) != std::string::npos) {
                LogEntry log;
                log.category = "Discord";
                log.triggerType = "Сервер/канал";
                log.source = path;
                log.matchedValue = trigger;
                log.weight = config.weights.discordMatch;
                log.timestamp = timestampNow();
                logger.addEntry(log);
            }
        }
    }
}

void DiscordScanner::run() {
    for (const auto &path : config.discordLogFiles) {
        processFile(path);
    }
}

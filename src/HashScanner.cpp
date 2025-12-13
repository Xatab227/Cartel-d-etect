#include "HashScanner.h"
#include "Sha256.h"
#include "Utility.h"

#include <fstream>
#include <iostream>
#include <regex>

HashScanner::HashScanner(const Config &config, Logger &logger) : config(config), logger(logger) {
    loadDatabase();
}

void HashScanner::loadDatabase() {
    std::ifstream file(config.hashDatabasePath);
    if (!file.is_open()) {
        std::cerr << "Не удалось открыть базу хешей: " << config.hashDatabasePath << "\n";
        return;
    }

    std::regex shaRegex("sha256:([0-9a-fA-F]{64})");
    std::regex md5Regex("md5:([0-9a-fA-F]{32})");
    std::regex sizeRegex("size:([0-9]+)");
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') {
            continue;
        }
        std::smatch match;
        HashSignature signature;
        if (std::regex_search(line, match, shaRegex)) {
            signature.sha256 = toLowerCopy(match[1]);
        }
        if (std::regex_search(line, match, md5Regex)) {
            signature.md5 = toLowerCopy(match[1]);
        }
        if (std::regex_search(line, match, sizeRegex)) {
            signature.size = static_cast<uintmax_t>(std::stoull(match[1]));
        }
        auto commentPos = line.find('#');
        if (commentPos != std::string::npos) {
            signature.label = line.substr(commentPos + 1);
        }
        if (!signature.sha256.empty()) {
            signatures[signature.sha256] = signature;
        }
    }
}

void HashScanner::scanDirectory(const std::filesystem::path &path) {
    if (!std::filesystem::exists(path)) {
        return;
    }

    for (auto const &entry : std::filesystem::recursive_directory_iterator(path)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        const auto hash = sha256File(entry.path());
        auto it = signatures.find(hash);
        if (it != signatures.end()) {
            LogEntry log;
            log.category = "Хеши";
            log.triggerType = "Хеш";
            log.source = entry.path().string();
            log.matchedValue = it->second.sha256 + " " + it->second.label;
            log.weight = config.weights.hashMatch;
            log.timestamp = timestampNow();
            logger.addEntry(log);
        }
    }
}

void HashScanner::run() {
    for (const auto &dir : config.scanDirectories) {
        scanDirectory(expandEnvironmentVariables(dir));
    }
}

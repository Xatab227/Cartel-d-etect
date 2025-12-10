#include "HashScanner.h"
#include "utils/SHA256.h"

#include <filesystem>
#include <fstream>
#include <chrono>
#include <ctime>

namespace fs = std::filesystem;

static std::string now() {
    auto tp = std::chrono::system_clock::now();
    std::time_t t = std::chrono::system_clock::to_time_t(tp);
    char buffer[32];
    std::strftime(buffer, sizeof(buffer), "%Y-%m-%d %H:%M:%S", std::localtime(&t));
    return buffer;
}

HashScanner::HashScanner(Logger &logger, const Weights &weights) : logger(logger), weights(weights) {}

bool HashScanner::loadDatabase(const std::string &path) {
    std::ifstream file(path);
    if (!file.is_open()) return false;
    std::string line;
    while (std::getline(file, line)) {
        if (line.empty()) continue;
        auto comma = line.find(',');
        if (comma == std::string::npos) continue;
        std::string category = line.substr(0, comma);
        std::string hash = line.substr(comma + 1);
        database[hash] = category;
    }
    return !database.empty();
}

void HashScanner::scan(const ScanPaths &paths) {
    scanDirectory(paths.recentPath);
    scanDirectory(paths.prefetchPath);
    for (const auto &extra : paths.extraPaths) {
        scanDirectory(extra);
    }
}

void HashScanner::scanDirectory(const std::string &path) {
    if (path.empty()) return;
    std::error_code ec;
    if (!fs::exists(path, ec)) return;
    for (auto &entry : fs::recursive_directory_iterator(path, fs::directory_options::skip_permission_denied, ec)) {
        if (!entry.is_regular_file()) continue;
        auto hash = SHA256::fromFile(entry.path().string());
        if (hash.empty()) continue;
        auto it = database.find(hash);
        if (it != database.end()) {
            LogEntry log;
            log.type = "Совпадение хеша";
            log.source = entry.path().string();
            log.matchedValue = it->first;
            log.weight = weights.hashMatchWeight;
            log.details = "Категория: " + it->second;
            log.timestamp = now();
            logger.logHashEvent(log);
        }
    }
}


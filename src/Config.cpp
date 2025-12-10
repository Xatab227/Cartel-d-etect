#include "Config.h"

#include <fstream>
#include <sstream>
#include <iostream>

namespace {
std::string trim(const std::string &s) {
    size_t start = s.find_first_not_of(" \t\n\r");
    if (start == std::string::npos) return "";
    size_t end = s.find_last_not_of(" \t\n\r");
    return s.substr(start, end - start + 1);
}
}

std::vector<std::string> Config::splitList(const std::string &line) {
    std::vector<std::string> result;
    std::stringstream ss(line);
    std::string item;
    while (std::getline(ss, item, ';')) {
        auto trimmed = trim(item);
        if (!trimmed.empty()) {
            result.push_back(trimmed);
        }
    }
    return result;
}

bool Config::load(const std::string &path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        std::cerr << "Не удалось открыть файл конфигурации: " << path << "\n";
        return false;
    }

    std::string line;
    while (std::getline(file, line)) {
        if (line.empty() || line[0] == '#') continue;
        auto pos = line.find('=');
        if (pos == std::string::npos) continue;
        std::string key = trim(line.substr(0, pos));
        std::string value = trim(line.substr(pos + 1));

        if (key == "hashDatabase") hashDatabasePath = value;
        else if (key == "keywordFile") keywordFilePath = value;
        else if (key == "siteListFile") siteListFilePath = value;
        else if (key == "browserLogPaths") browserLogs = splitList(value);
        else if (key == "discordLogPaths") discordLogs = splitList(value);
        else if (key == "discordServers") discordServersList = splitList(value);
        else if (key == "extraScanPaths") scanPaths.extraPaths = splitList(value);
        else if (key == "recentPath") scanPaths.recentPath = value;
        else if (key == "prefetchPath") scanPaths.prefetchPath = value;
        else if (key == "hashWeight") weightConfig.hashMatchWeight = std::stoi(value);
        else if (key == "keywordWeight") weightConfig.keywordWeight = std::stoi(value);
        else if (key == "siteWeight") weightConfig.siteWeight = std::stoi(value);
        else if (key == "discordWeight") weightConfig.discordWeight = std::stoi(value);
        else if (key == "outputLog") outputLog = value;
    }

    return true;
}


#include "Config.h"
#include "Utility.h"

#include <fstream>
#include <regex>
#include <stdexcept>
#include <string>

namespace {
std::vector<std::string> parseStringArray(const std::string &key, const std::string &data) {
    std::regex arrayRegex("\"" + key + "\"\\s*:\\s*\\[(.*?)\\]");
    std::smatch match;
    std::vector<std::string> values;
    if (std::regex_search(data, match, arrayRegex)) {
        std::string content = match[1];
        std::regex valueRegex("\\\"(.*?)\\\"");
        auto begin = std::sregex_iterator(content.begin(), content.end(), valueRegex);
        auto end = std::sregex_iterator();
        for (auto it = begin; it != end; ++it) {
            values.push_back(expandEnvironmentVariables((*it)[1]));
        }
    }
    return values;
}

std::string parseString(const std::string &key, const std::string &data) {
    std::regex valueRegex("\"" + key + "\"\\s*:\\s*\\\"(.*?)\\\"");
    std::smatch match;
    if (std::regex_search(data, match, valueRegex)) {
        return expandEnvironmentVariables(match[1]);
    }
    return {};
}

int parseInt(const std::string &key, const std::string &data, int fallback) {
    std::regex valueRegex("\"" + key + "\"\\s*:\\s*([0-9]+)");
    std::smatch match;
    if (std::regex_search(data, match, valueRegex)) {
        return std::stoi(match[1]);
    }
    return fallback;
}
} // namespace

Config ConfigLoader::loadFromFile(const std::string &path) {
    std::ifstream file(path);
    if (!file.is_open()) {
        throw std::runtime_error("Не удалось открыть файл конфигурации: " + path);
    }

    std::string content((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    Config config;
    config.hashDatabasePath = parseString("hashDatabase", content);
    config.triggerWordsPath = parseString("triggerWordsFile", content);
    config.scanDirectories = parseStringArray("scanDirectories", content);
    config.browserLogFiles = parseStringArray("browserLogFiles", content);
    config.discordLogFiles = parseStringArray("discordLogFiles", content);
    config.keywords = parseStringArray("keywords", content);
    config.domains = parseStringArray("domains", content);

    config.weights.hashMatch = parseInt("hashMatch", content, config.weights.hashMatch);
    config.weights.keywordMatch = parseInt("keywordMatch", content, config.weights.keywordMatch);
    config.weights.domainMatch = parseInt("domainMatch", content, config.weights.domainMatch);
    config.weights.discordMatch = parseInt("discordMatch", content, config.weights.discordMatch);

    return config;
}

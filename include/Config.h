#pragma once

#include <string>
#include <unordered_map>
#include <vector>

struct RiskWeights {
    int hashMatch = 40;
    int keywordMatch = 15;
    int domainMatch = 20;
    int discordMatch = 25;
};

struct Config {
    std::string hashDatabasePath;
    std::string triggerWordsPath;
    std::vector<std::string> scanDirectories;
    std::vector<std::string> browserLogFiles;
    std::vector<std::string> discordLogFiles;
    std::vector<std::string> keywords;
    std::vector<std::string> domains;
    RiskWeights weights;
};

class ConfigLoader {
public:
    static Config loadFromFile(const std::string &path);
};

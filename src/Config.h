#pragma once

#include <string>
#include <vector>
#include <unordered_map>

struct ScanPaths {
    std::string recentPath;
    std::string prefetchPath;
    std::vector<std::string> extraPaths;
};

struct Weights {
    int hashMatchWeight = 40;
    int keywordWeight = 15;
    int siteWeight = 20;
    int discordWeight = 25;
};

class Config {
public:
    bool load(const std::string &path);

    const std::string &hashDatabase() const { return hashDatabasePath; }
    const std::string &keywordFile() const { return keywordFilePath; }
    const std::string &siteListFile() const { return siteListFilePath; }
    const std::vector<std::string> &browserLogFiles() const { return browserLogs; }
    const std::vector<std::string> &discordLogFiles() const { return discordLogs; }
    const std::vector<std::string> &discordServers() const { return discordServersList; }
    const ScanPaths &paths() const { return scanPaths; }
    const Weights &weights() const { return weightConfig; }
    const std::string &outputLogFile() const { return outputLog; }

private:
    std::string hashDatabasePath;
    std::string keywordFilePath;
    std::string siteListFilePath;
    std::vector<std::string> browserLogs;
    std::vector<std::string> discordLogs;
    std::vector<std::string> discordServersList;
    ScanPaths scanPaths;
    Weights weightConfig;
    std::string outputLog = "scan_log.txt";

    static std::vector<std::string> splitList(const std::string &line);
};


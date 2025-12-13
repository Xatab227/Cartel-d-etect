#pragma once

#include <fstream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

struct LogEntry {
    std::string category;
    std::string triggerType;
    std::string source;
    std::string matchedValue;
    int weight = 0;
    std::string timestamp;
};

class Logger {
public:
    explicit Logger(const std::string &filePath);
    void addEntry(const LogEntry &entry);
    void flush();
    const std::vector<LogEntry> &getCategory(const std::string &category) const;
    int countCategory(const std::string &category) const;

private:
    std::string logPath;
    mutable std::mutex mutex;
    std::unordered_map<std::string, std::vector<LogEntry>> entries;
    void appendToFile(const LogEntry &entry);
};

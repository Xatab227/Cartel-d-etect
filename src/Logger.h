#pragma once
#include <string>
#include <vector>
#include <fstream>
#include <mutex>

struct LogEntry {
    std::string type;
    std::string source;
    std::string matchedValue;
    int weight = 0;
    std::string timestamp;
    std::string details;
};

class Logger {
public:
    explicit Logger(const std::string &filePath);
    void logHashEvent(const LogEntry &entry);
    void logBrowserEvent(const LogEntry &entry);
    void logDiscordEvent(const LogEntry &entry);
    void logSummary(const std::string &message);

    const std::vector<LogEntry> &hashLog() const { return hashEvents; }
    const std::vector<LogEntry> &browserLog() const { return browserEvents; }
    const std::vector<LogEntry> &discordLog() const { return discordEvents; }

private:
    std::ofstream stream;
    std::vector<LogEntry> hashEvents;
    std::vector<LogEntry> browserEvents;
    std::vector<LogEntry> discordEvents;
    std::mutex mutex;

    void writeLine(const std::string &prefix, const LogEntry &entry);
};


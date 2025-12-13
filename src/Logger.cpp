#include "Logger.h"

#include <iomanip>
#include <iostream>
#include <sstream>

Logger::Logger(const std::string &filePath) : logPath(filePath) {
    std::ofstream file(logPath, std::ios::trunc);
    if (file.is_open()) {
        file << "===== Старт сканирования =====\n";
    }
}

void Logger::appendToFile(const LogEntry &entry) {
    std::ofstream file(logPath, std::ios::app);
    if (!file.is_open()) {
        return;
    }
    file << "[" << entry.timestamp << "] " << entry.category << " | " << entry.triggerType
         << " | " << entry.source << " | " << entry.matchedValue << " | вес " << entry.weight << "\n";
}

void Logger::addEntry(const LogEntry &entry) {
    std::lock_guard<std::mutex> lock(mutex);
    entries[entry.category].push_back(entry);
    appendToFile(entry);
}

void Logger::flush() {
    std::lock_guard<std::mutex> lock(mutex);
    std::ofstream file(logPath, std::ios::app);
    file << "===== Завершение сканирования =====\n";
}

const std::vector<LogEntry> &Logger::getCategory(const std::string &category) const {
    static const std::vector<LogEntry> empty;
    auto it = entries.find(category);
    if (it != entries.end()) {
        return it->second;
    }
    return empty;
}

int Logger::countCategory(const std::string &category) const {
    auto it = entries.find(category);
    if (it != entries.end()) {
        return static_cast<int>(it->second.size());
    }
    return 0;
}

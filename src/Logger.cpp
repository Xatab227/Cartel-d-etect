#include "Logger.h"

#include <iostream>

Logger::Logger(const std::string &filePath) : stream(filePath, std::ios::out | std::ios::trunc) {
    if (!stream.is_open()) {
        std::cerr << "Не удалось открыть файл лога: " << filePath << "\n";
    }
}

void Logger::writeLine(const std::string &prefix, const LogEntry &entry) {
    if (!stream.is_open()) return;
    stream << prefix << " [" << entry.timestamp << "] "
           << entry.type << " | источник: " << entry.source
           << " | совпадение: " << entry.matchedValue
           << " | вес: " << entry.weight
           << " | детали: " << entry.details
           << "\n";
}

void Logger::logHashEvent(const LogEntry &entry) {
    std::lock_guard<std::mutex> lock(mutex);
    hashEvents.push_back(entry);
    writeLine("[HASH]", entry);
}

void Logger::logBrowserEvent(const LogEntry &entry) {
    std::lock_guard<std::mutex> lock(mutex);
    browserEvents.push_back(entry);
    writeLine("[BROWSER]", entry);
}

void Logger::logDiscordEvent(const LogEntry &entry) {
    std::lock_guard<std::mutex> lock(mutex);
    discordEvents.push_back(entry);
    writeLine("[DISCORD]", entry);
}

void Logger::logSummary(const std::string &message) {
    if (!stream.is_open()) return;
    std::lock_guard<std::mutex> lock(mutex);
    stream << message << "\n";
}


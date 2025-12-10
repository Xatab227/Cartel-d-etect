#include "MainWindow.h"

#include <iostream>
#include <string>

namespace {
std::string colorForRisk(int risk) {
    if (risk <= 20) return "🟢";
    if (risk <= 50) return "💛";
    if (risk > 70) return "🔴";
    return "🟠";
}
}

MainWindow::MainWindow(const Logger &logger, const RiskReport &report) : logger(logger), report(report) {}

void MainWindow::renderProgressBar() const {
    int filled = report.totalRisk / 5; // 20 segments
    std::string bar(filled, '#');
    bar.resize(20, '-');
    std::cout << "\nОценка риска: " << report.totalRisk << "% " << colorForRisk(report.totalRisk) << "\n";
    std::cout << "[" << bar << "]" << std::endl;
}

void MainWindow::renderLogBlock(const std::string &title, const std::vector<LogEntry> &entries) const {
    std::cout << "\n=== " << title << " (" << entries.size() << ") ===\n";
    for (const auto &entry : entries) {
        std::cout << " - " << entry.type << ": " << entry.matchedValue
                  << " | источник: " << entry.source
                  << " | вес: " << entry.weight
                  << " | время: " << entry.timestamp << "\n";
        std::cout << "   детали: " << entry.details << "\n";
    }
}

void MainWindow::render() {
    std::cout << "=== Форензик-античит сканер ===\n";
    renderProgressBar();
    std::cout << "Триггеры по хешам: " << report.hashTriggers
              << ", браузер: " << report.browserTriggers
              << ", Discord: " << report.discordTriggers << "\n";

    renderLogBlock("Лог хешей", logger.hashLog());
    renderLogBlock("Лог браузера", logger.browserLog());
    renderLogBlock("Лог Discord", logger.discordLog());
}


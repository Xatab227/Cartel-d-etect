#pragma once
#include "Logger.h"
#include "RiskCalculator.h"

class MainWindow {
public:
    MainWindow(const Logger &logger, const RiskReport &report);
    void render();

private:
    const Logger &logger;
    RiskReport report;

    void renderProgressBar() const;
    void renderLogBlock(const std::string &title, const std::vector<LogEntry> &entries) const;
};


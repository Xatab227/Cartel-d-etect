#pragma once
#include <vector>
#include "Logger.h"
#include "Config.h"

struct RiskReport {
    int totalRisk = 0;
    int hashTriggers = 0;
    int browserTriggers = 0;
    int discordTriggers = 0;
};

class RiskCalculator {
public:
    explicit RiskCalculator(const Weights &weights) : weights(weights) {}
    RiskReport calculate(const std::vector<LogEntry> &hash,
                         const std::vector<LogEntry> &browser,
                         const std::vector<LogEntry> &discord);

private:
    Weights weights;
};


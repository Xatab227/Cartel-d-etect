#pragma once

#include "Logger.h"
#include "Config.h"

class RiskCalculator {
public:
    explicit RiskCalculator(const RiskWeights &weights);
    void include(const LogEntry &entry);
    int totalRisk() const;

    int hashTriggers() const { return hashCount; }
    int browserTriggers() const { return browserCount; }
    int discordTriggers() const { return discordCount; }

private:
    RiskWeights weights;
    int riskScore = 0;
    int hashCount = 0;
    int browserCount = 0;
    int discordCount = 0;
};

#include "RiskCalculator.h"

RiskCalculator::RiskCalculator(const RiskWeights &weights) : weights(weights) {}

void RiskCalculator::include(const LogEntry &entry) {
    if (entry.category == "Хеши") {
        hashCount++;
        riskScore += weights.hashMatch;
    } else if (entry.category == "Браузер") {
        browserCount++;
        if (entry.triggerType == "Домен") {
            riskScore += weights.domainMatch;
        } else {
            riskScore += weights.keywordMatch;
        }
    } else if (entry.category == "Discord") {
        discordCount++;
        riskScore += weights.discordMatch;
    }
    if (riskScore > 100) {
        riskScore = 100;
    }
}

int RiskCalculator::totalRisk() const {
    if (riskScore > 100) {
        return 100;
    }
    return riskScore;
}

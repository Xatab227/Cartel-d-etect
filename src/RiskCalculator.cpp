#include "RiskCalculator.h"

RiskReport RiskCalculator::calculate(const std::vector<LogEntry> &hash,
                                     const std::vector<LogEntry> &browser,
                                     const std::vector<LogEntry> &discord) {
    RiskReport report;
    report.hashTriggers = static_cast<int>(hash.size());
    report.browserTriggers = static_cast<int>(browser.size());
    report.discordTriggers = static_cast<int>(discord.size());

    int risk = 0;
    risk += report.hashTriggers * weights.hashMatchWeight;
    risk += report.browserTriggers * weights.keywordWeight;
    risk += report.browserTriggers * weights.siteWeight; // доп вклад за сайты
    risk += report.discordTriggers * weights.discordWeight;

    if (risk > 100) risk = 100;
    report.totalRisk = risk;
    return report;
}


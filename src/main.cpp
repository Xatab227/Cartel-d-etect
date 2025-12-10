#include "Config.h"
#include "Logger.h"
#include "HashScanner.h"
#include "BrowserScanner.h"
#include "DiscordScanner.h"
#include "RiskCalculator.h"
#include "ui/MainWindow.h"

#include <iostream>

int main() {
    Config config;
    if (!config.load("config/config.ini")) {
        std::cerr << "Используется конфигурация по умолчанию\n";
    }

    Logger logger(config.outputLogFile());

    HashScanner hashScanner(logger, config.weights());
    if (!config.hashDatabase().empty()) {
        if (!hashScanner.loadDatabase(config.hashDatabase())) {
            std::cerr << "Не удалось загрузить базу хешей\n";
        }
    }

    BrowserScanner browserScanner(logger, config.weights());
    browserScanner.loadKeywords(config.keywordFile(), config.siteListFile());

    DiscordScanner discordScanner(logger, config.weights());
    discordScanner.loadKeywords(config.keywordFile(), config.discordServers());

    hashScanner.scan(config.paths());
    browserScanner.scan(config.browserLogFiles());
    discordScanner.scan(config.discordLogFiles());

    RiskCalculator calculator(config.weights());
    auto report = calculator.calculate(logger.hashLog(), logger.browserLog(), logger.discordLog());

    std::string summary = "Итог: риск " + std::to_string(report.totalRisk) + "% ("
        + std::to_string(report.hashTriggers) + " хешей, "
        + std::to_string(report.browserTriggers) + " браузер, "
        + std::to_string(report.discordTriggers) + " Discord)";
    logger.logSummary(summary);

    MainWindow window(logger, report);
    window.render();

    return 0;
}


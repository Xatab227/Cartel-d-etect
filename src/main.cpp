#include "BrowserScanner.h"
#include "Config.h"
#include "DiscordScanner.h"
#include "HashScanner.h"
#include "Logger.h"
#include "RiskCalculator.h"
#include "UI/MainWindow.h"
#include "Utility.h"

#include <iostream>

#ifdef FS_HAS_QT
#include <QApplication>
#endif

int main(int argc, char **argv) {
    try {
        Config config = ConfigLoader::loadFromFile("config/config.json");
        Logger logger("scan_log.txt");
        RiskCalculator calculator(config.weights);

        HashScanner hashScanner(config, logger);
        BrowserScanner browserScanner(config, logger);
        DiscordScanner discordScanner(config, logger);

        hashScanner.run();
        browserScanner.run();
        discordScanner.run();

        for (const auto &entry : logger.getCategory("Хеши")) {
            calculator.include(entry);
        }
        for (const auto &entry : logger.getCategory("Браузер")) {
            calculator.include(entry);
        }
        for (const auto &entry : logger.getCategory("Discord")) {
            calculator.include(entry);
        }

        logger.flush();

#ifdef FS_HAS_QT
        QApplication app(argc, argv);
        MainWindow window(logger, calculator);
        window.showWindow();
        return app.exec();
#else
        std::cout << "Итоговый риск: " << calculator.totalRisk() << "%\n";
        std::cout << "Срабатывания по хешам: " << calculator.hashTriggers() << "\n";
        std::cout << "Совпадения в браузере: " << calculator.browserTriggers() << "\n";
        std::cout << "Совпадения Discord: " << calculator.discordTriggers() << "\n";
        return 0;
#endif
    } catch (const std::exception &ex) {
        std::cerr << "Ошибка: " << ex.what() << "\n";
        return 1;
    }
}

#pragma once

#include "Config.h"
#include "Logger.h"

class DiscordScanner {
public:
    DiscordScanner(const Config &config, Logger &logger);
    void run();

private:
    Config config;
    Logger &logger;
    void processFile(const std::string &path);
};

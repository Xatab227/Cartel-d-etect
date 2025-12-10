#pragma once
#include <string>
#include <vector>
#include "Logger.h"
#include "Config.h"

class DiscordScanner {
public:
    DiscordScanner(Logger &logger, const Weights &weights);
    void loadKeywords(const std::string &keywordFile, const std::vector<std::string> &serverList);
    void scan(const std::vector<std::string> &files);

private:
    Logger &logger;
    Weights weights;
    std::vector<std::string> keywords;
    std::vector<std::string> servers;

    void analyzeLine(const std::string &line, const std::string &source);
};


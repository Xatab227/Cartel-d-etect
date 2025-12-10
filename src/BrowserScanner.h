#pragma once
#include <string>
#include <vector>
#include "Logger.h"
#include "Config.h"

class BrowserScanner {
public:
    BrowserScanner(Logger &logger, const Weights &weights);
    void loadKeywords(const std::string &keywordFile, const std::string &siteFile);
    void scan(const std::vector<std::string> &files);

private:
    Logger &logger;
    Weights weights;
    std::vector<std::string> keywords;
    std::vector<std::string> sites;

    void analyzeLine(const std::string &line, const std::string &source);
};


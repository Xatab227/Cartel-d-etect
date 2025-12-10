#pragma once
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>
#include "Logger.h"
#include "Config.h"

class HashScanner {
public:
    explicit HashScanner(Logger &logger, const Weights &weights);
    bool loadDatabase(const std::string &path);
    void scan(const ScanPaths &paths);

private:
    Logger &logger;
    Weights weights;
    std::unordered_map<std::string, std::string> database; // hash -> category

    void scanDirectory(const std::string &path);
};


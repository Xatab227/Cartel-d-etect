#pragma once

#include "Config.h"
#include "Logger.h"

#include <filesystem>
#include <map>

struct HashSignature {
    std::string sha256;
    std::string md5;
    uintmax_t size = 0;
    std::string label;
};

class HashScanner {
public:
    HashScanner(const Config &config, Logger &logger);
    void run();

private:
    Config config;
    Logger &logger;
    std::map<std::string, HashSignature> signatures;

    void loadDatabase();
    void scanDirectory(const std::filesystem::path &path);
};

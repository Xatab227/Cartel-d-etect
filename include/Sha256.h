#pragma once

#include <array>
#include <cstdint>
#include <filesystem>
#include <string>

std::string sha256(const std::string &input);
std::string sha256File(const std::filesystem::path &path);

#pragma once
#include <memory>
#include <iostream>
#include <string>
#include <vector>

namespace ufrontend {

class ConfigReader
{
private:
    std::string mConfigFilePath;

public:
    ConfigReader(const std::string &ConfigFilePath);
    virtual ~ConfigReader();

public:
    // Get/Set
    // Get the config file path
    const std::string getConfigFilePath() const;

    // Set the config file path
    void setConfigFilePath(const std::string &ConfigFilePath);

public:
    // Static
    static std::unique_ptr<ConfigReader> get(const std::string &ConfigFilePath);
};

} // namespace ufrontend

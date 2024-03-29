#pragma once
#include <cassert>
#include <memory>
#include <iostream>
#include <string>
#include <vector>
#include <optional>

#include <UnknownUtils/unknown/tinyxml2/tinyxml2.h>

namespace ufrontend {

class ConfigReader
{
public:
    struct FunctionItem
    {
        std::string Name;
        std::vector<std::string> Attributes;
    };

private:
    std::string mConfigFilePath;
    std::string mConfigName;
    unknown::XMLDocument mXMLDocument;
    std::vector<FunctionItem> mFunctionItems;

public:
    ConfigReader(const std::string &ConfigFilePath);
    virtual ~ConfigReader();

public:
    // Parse
    bool ParseConfig();

private:
    // Parse
    void ParseFunctionInfo(unknown::XMLElement *Root);

public:
    // Get/Set
    // Get the config file path
    const std::string getConfigFilePath() const;

    // Set the config file path
    void setConfigFilePath(const std::string &ConfigFilePath);

    // Get the config name
    const std::string getConfigName() const;

    // Set the config name
    void setConfigName(const std::string &ConfigName);

    // Get the function items
    const std::vector<FunctionItem> &getFunctionItems() const;

    // Set the function items
    void setFunctionItems(const std::vector<FunctionItem> &Items);

    // Get the function attributes
    const std::vector<std::string> getFunctionAttributes(const std::string &FunctionName) const;

public:
    // Static
    static std::unique_ptr<ConfigReader> get(const std::string &ConfigFilePath);
};

} // namespace ufrontend

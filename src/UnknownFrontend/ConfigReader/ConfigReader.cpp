#include "ConfigReader.h"

namespace ufrontend {

ConfigReader::ConfigReader(const std::string &ConfigFilePath) : mConfigFilePath(ConfigFilePath)
{
    //
}

ConfigReader::~ConfigReader()
{
    //
}
////////////////////////////////////////////////////////////
// Get/Set
// Get the config file path
const std::string
ConfigReader::getConfigFilePath() const
{
    return mConfigFilePath;
}

// Set the config file path
void
ConfigReader::setConfigFilePath(const std::string &ConfigFilePath)
{
    mConfigFilePath = ConfigFilePath;
}

////////////////////////////////////////////////////////////
// Static
std::unique_ptr<ConfigReader>
ConfigReader::get(const std::string &ConfigFilePath)
{
    return std::make_unique<ConfigReader>(ConfigFilePath);
}

} // namespace ufrontend

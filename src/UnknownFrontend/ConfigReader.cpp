#include "ConfigReader.h"

namespace ufrontend {

ConfigReader::ConfigReader(const std::string &ConfigFilePath) : mConfigFilePath(ConfigFilePath), mConfigName("")
{
    assert(!ConfigFilePath.empty());
}

ConfigReader::~ConfigReader()
{
    //
}

// Parse
bool
ConfigReader::ParseConfig()
{
    mFunctionItems.clear();

    if (mConfigFilePath.empty())
    {
        return false;
    }

    auto XmlRet = mXMLDocument.LoadFile(mConfigFilePath.c_str());
    if (XmlRet != unknown::XML_SUCCESS)
    {
        return false;
    }

    auto Root = mXMLDocument.RootElement();
    if (Root == nullptr)
    {
        return false;
    }

    auto ConfigName = Root->Attribute("name");
    if (ConfigName)
    {
        mConfigName = ConfigName;
    }

    // Parse function info
    ParseFunctionInfo(Root);

    return true;
}

void
ConfigReader::ParseFunctionInfo(unknown::XMLElement *Root)
{
    assert(Root);

    // Parse function info
    for (unknown::XMLElement *CurrenteleElement = Root->FirstChildElement("f"); CurrenteleElement;
         CurrenteleElement = CurrenteleElement->NextSiblingElement("f"))
    {
        auto Name = CurrenteleElement->Attribute("name");
        if (Name)
        {
            FunctionItem Item{};
            Item.Name = Name;
            for (int i = 1; 1; ++i)
            {
                auto AttrIdx = std::string("attribute") + std::to_string(i);
                auto Attr = CurrenteleElement->Attribute(AttrIdx.c_str());
                if (Attr)
                {
                    Item.Attributes.push_back(Attr);
                }
                else
                {
                    break;
                }
            }

            mFunctionItems.push_back(Item);
        }
    }
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

// Get the config name
const std::string
ConfigReader::getConfigName() const
{
    return mConfigName;
}

// Set the config name
void
ConfigReader::setConfigName(const std::string &ConfigName)
{
    mConfigName = ConfigName;
}

// Get the function items
const std::vector<ConfigReader::FunctionItem> &
ConfigReader::getFunctionItems() const
{
    return mFunctionItems;
}

// Set the function items
void
ConfigReader::setFunctionItems(const std::vector<ConfigReader::FunctionItem> &Items)
{
    mFunctionItems = Items;
}

// Get the function attributes
const std::vector<std::string>
ConfigReader::getFunctionAttributes(const std::string &FunctionName) const
{
    std::vector<std::string> Attributes;
    for (auto &Item : getFunctionItems())
    {
        if (Item.Name.compare(FunctionName) == 0)
        {
            Attributes = Item.Attributes;
            break;
        }
    }

    return Attributes;
}

////////////////////////////////////////////////////////////
// Static
std::unique_ptr<ConfigReader>
ConfigReader::get(const std::string &ConfigFilePath)
{
    return std::make_unique<ConfigReader>(ConfigFilePath);
}

} // namespace ufrontend

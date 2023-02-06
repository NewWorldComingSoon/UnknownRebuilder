#include "TranslatorImpl.h"
#include "Error.h"

namespace ufrontend {

UnknownFrontendTranslatorImpl::UnknownFrontendTranslatorImpl(
    uir::Context &C,
    const Platform Platform,
    const std::string &BinaryFile,
    const std::string &SymbolFile,
    const std::string &ConfigFile,
    bool AnalyzeAllFunctions) :
    mPlatform(Platform),
    mContext(C),
    mBinaryFile(BinaryFile),
    mSymbolFile(SymbolFile),
    mConfigFile(ConfigFile),
    mEnableAnalyzeAllFunctions(AnalyzeAllFunctions),
    mCapstoneHandle(0),
    mCurPtrBegin(0),
    mCurPtrEnd(0),
    mCurFunction(nullptr)
{
    switch (C.getArch())
    {
    case uir::Context::Arch::ArchX86:
        mTarget = unknown::CreateTargetForX86(C.getModeBits());
        break;
    case uir::Context::Arch::ArchARM:
        mTarget = unknown::CreateTargetForARM(C.getModeBits());
        break;
    default:
        // TODO
        break;
    }
}

UnknownFrontendTranslatorImpl::~UnknownFrontendTranslatorImpl()
{
    closeCapstoneHandle();

    // Clear mVirtualRegisterInfoMap
    for (auto &Item : mVirtualRegisterInfoMap)
    {
        auto &VParentRegInfo = Item.second;

        for (auto &VRegInfoItem : VParentRegInfo)
        {
            auto &VRegInfo = VRegInfoItem.second;
            if (VRegInfo.RegPtr != nullptr && VRegInfo.RegPtr->user_empty())
            {
                delete VRegInfo.RegPtr;
                VRegInfo.RegPtr = nullptr;
            }

            if (VRegInfo.SavedRegVal != nullptr && VRegInfo.SavedRegVal->user_empty())
            {
                delete VRegInfo.SavedRegVal;
                VRegInfo.SavedRegVal = nullptr;
            }
        }
    }
}

////////////////////////////////////////////////////////////
// Init
// Init the translator
void
UnknownFrontendTranslatorImpl::initTranslator()
{
    initConfig();
    openCapstoneHandle();
    initSymbolParser();
    initBinary();
    initTranslateInstruction();
}

////////////////////////////////////////////////////////////
// Config
// Init the config
void
UnknownFrontendTranslatorImpl::initConfig()
{
    if (mConfigFile.empty())
    {
        return;
    }

    mConfigReader = ConfigReader::get(mConfigFile);
    assert(mConfigReader);

    if (!mConfigReader->ParseConfig())
    {
        std::cerr << UFRONTEND_ERROR_PREFIX "ParseConfig failed" << std::endl;
        std::abort();
    }
}

////////////////////////////////////////////////////////////
// Get/Set
// Get the context of this translator
uir::Context &
UnknownFrontendTranslatorImpl::getContext() const
{
    return mContext;
}

// Get the Binary File
const std::string &
UnknownFrontendTranslatorImpl::getBinaryFile() const
{
    return mBinaryFile;
}

// Get the Symbol File
const std::string &
UnknownFrontendTranslatorImpl::getSymbolFile() const
{
    return mSymbolFile;
}

// Get the Config File
const std::string &
UnknownFrontendTranslatorImpl::getConfigFile() const
{
    return mConfigFile;
}

// Get the capstone handle
csh
UnknownFrontendTranslatorImpl::getCapstoneHandle() const
{
    return mCapstoneHandle;
}

// Set the capstone handle
void
UnknownFrontendTranslatorImpl::setCapstoneHandle(csh CapstoneHandle)
{
    mCapstoneHandle = CapstoneHandle;
}

// Get the begin of current pointer
const uint64_t
UnknownFrontendTranslatorImpl::getCurPtrBegin() const
{
    return mCurPtrBegin;
}

// Get the end of current pointer
const uint64_t
UnknownFrontendTranslatorImpl::getCurPtrEnd() const
{
    return mCurPtrEnd;
}

// Set the begin of current pointer
void
UnknownFrontendTranslatorImpl::setCurPtrBegin(uint64_t Ptr)
{
    mCurPtrBegin = Ptr;
}

// Set the end of current pointer
void
UnknownFrontendTranslatorImpl::setCurPtrEnd(uint64_t Ptr)
{
    mCurPtrEnd = Ptr;
}

// Get the current function
const uir::Function *
UnknownFrontendTranslatorImpl::getCurFunction() const
{
    return mCurFunction;
}

// Set the current function
void
UnknownFrontendTranslatorImpl::setCurFunction(uir::Function *Function)
{
    mCurFunction = Function;
}

// Get the platform
const UnknownFrontendTranslator::Platform
UnknownFrontendTranslatorImpl::getPlatform() const
{
    return mPlatform;
}

// Set the platform
void
UnknownFrontendTranslatorImpl::setPlatform(Platform Plat)
{
    mPlatform = Plat;
}

// Get EnableAnalyzeAllFunctions
const bool
UnknownFrontendTranslatorImpl::getEnableAnalyzeAllFunctions() const
{
    return mEnableAnalyzeAllFunctions;
}

// Set EnableAnalyzeAllFunctions
void
UnknownFrontendTranslatorImpl::setEnableAnalyzeAllFunctions(bool Set)
{
    mEnableAnalyzeAllFunctions = Set;
}

////////////////////////////////////////////////////////////
// Register
// Get the register name with index by register id
std::string
UnknownFrontendTranslatorImpl::getRegisterNameWithIndex(uint32_t RegID, uint32_t Index)
{
    auto RegName = getRegisterName(RegID);
    return getRegisterNameWithIndex(RegName, Index);
}

// Get the register name with index by register name
std::string
UnknownFrontendTranslatorImpl::getRegisterNameWithIndex(unknown::StringRef RegName, uint32_t Index)
{
    std::string RegNameWithIndex = "";
    if (!RegName.empty())
    {
        RegNameWithIndex += RegName;
        RegNameWithIndex += std::to_string(Index);
    }

    return RegNameWithIndex;
}

// Get the register name with index by default by register id
std::string
UnknownFrontendTranslatorImpl::getRegisterNameWithIndexByDefault(uint32_t RegID)
{
    return getRegisterNameWithIndex(RegID, mRegisterCounterMap[RegID]++);
}

// Get the register name with index by default by name
std::string
UnknownFrontendTranslatorImpl::getRegisterNameWithIndexByDefault(unknown::StringRef RegName)
{
    auto RegID = getRegisterID(RegName.str());
    return getRegisterNameWithIndex(RegName, mRegisterCounterMap[RegID]++);
}

// Get the virtual register information by register id
std::optional<std::unordered_map<uint32_t, UnknownFrontendTranslatorImpl::VirtualRegisterInfo> *>
UnknownFrontendTranslatorImpl::getVirtualRegisterInfo(uint32_t RegID)
{
    auto ParentRegID = getRegisterParentID(RegID);
    auto VRegID = getVirtualRegisterID(RegID);

    // X86_REG_INVALID = 0
    // ARM64_REG_INVALID = 0
    // TODO: This should be expressed in a common macro
    constexpr uint32_t REG_INVALID = X86_REG_INVALID;
    if (ParentRegID == REG_INVALID)
    {
        return {};
    }

    auto insertVRegInfo2Map =
        [this](uint32_t RegID, uint32_t VRegID, std::unordered_map<uint32_t, VirtualRegisterInfo> &Map) {
            // [VRegID, VRegInfo]
            VirtualRegisterInfo VRegInfo{};
            VRegInfo.TypeBits = getRegisterTypeBits(RegID);
            VRegInfo.IsHigh8Bits = VRegInfo.TypeBits == 8 ? IsRegisterTypeHigh8Bits(RegID) : false;
            VRegInfo.IsUpdated = false;
            VRegInfo.RawRegID = RegID;
            VRegInfo.VirtualRegID = VRegID;
            VRegInfo.RegPtr = nullptr;
            VRegInfo.SavedRegVal = nullptr;

            // Insert to map
            Map.insert({VRegInfo.VirtualRegID, VRegInfo});
        };

    auto ItFindParentRegID = mVirtualRegisterInfoMap.find(ParentRegID);
    if (ItFindParentRegID != mVirtualRegisterInfoMap.end())
    {
        // Already exists
        auto ItFindVRegID = ItFindParentRegID->second.find(VRegID);
        if (ItFindVRegID == ItFindParentRegID->second.end())
        {
            // Not exists
            // Insert [VRegID, VRegInfo]
            insertVRegInfo2Map(RegID, VRegID, ItFindParentRegID->second);
        }
    }
    else
    {
        // Not exists
        // [ParentID, [VRegID, VRegInfo]]
        std::unordered_map<uint32_t, VirtualRegisterInfo> VMap;
        insertVRegInfo2Map(RegID, VRegID, VMap);
        mVirtualRegisterInfoMap.insert({ParentRegID, VMap});
    }

    return &mVirtualRegisterInfoMap[ParentRegID];
}

} // namespace ufrontend

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
        auto &VRegInfo = Item.second;
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
// Get the virtual register information by register id
std::optional<UnknownFrontendTranslatorImpl::VirtualRegisterInfo *>
UnknownFrontendTranslatorImpl::getVirtualRegisterInfo(uint32_t RegID)
{
    auto VRegID = getVirtualRegisterID(RegID);
    // X86_REG_INVALID = 0
    // ARM64_REG_INVALID = 0
    // TODO: This should be expressed in a common macro
    constexpr uint32_t V_REG_INVALID = X86_REG_INVALID;
    if (VRegID == V_REG_INVALID)
    {
        return {};
    }

    auto ItFind = mVirtualRegisterInfoMap.find(VRegID);
    if (ItFind != mVirtualRegisterInfoMap.end())
    {
        // Already exists
        return &ItFind->second;
    }
    else
    {
        // Insert [VRegID, VRegInfo]
        VirtualRegisterInfo VRegInfo{};
        VRegInfo.TypeBits = getRegisterTypeBits(RegID);
        VRegInfo.IsHigh8Bits = VRegInfo.TypeBits == 8 ? IsRegisterTypeHigh8Bits(RegID) : false;
        VRegInfo.IsUpdated = false;
        VRegInfo.RawRegID = RegID;
        VRegInfo.RegPtr = nullptr;
        VRegInfo.SavedRegVal = nullptr;
        mVirtualRegisterInfoMap.insert({VRegID, VRegInfo});

        return &mVirtualRegisterInfoMap[VRegID];
    }
}

} // namespace ufrontend

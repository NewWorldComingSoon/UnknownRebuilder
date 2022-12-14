#include "TranslatorImpl.h"

namespace ufrontend {

UnknownFrontendTranslatorImpl::UnknownFrontendTranslatorImpl(
    uir::Context &C,
    const Platform Platform,
    const std::string &BinaryFile,
    const std::string &SymbolFile) :
    mPlatform(Platform),
    mContext(C),
    mBinaryFile(BinaryFile),
    mSymbolFile(SymbolFile),
    mCapstoneHandle(0),
    mCurPtrBegin(0),
    mCurPtrEnd(0),
    mCurFunction(nullptr)
{
    openCapstoneHandle();
    initSymbolParser();
    initBinary();
}

UnknownFrontendTranslatorImpl::~UnknownFrontendTranslatorImpl()
{
    closeCapstoneHandle();
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
    assert(Ptr);
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

} // namespace ufrontend

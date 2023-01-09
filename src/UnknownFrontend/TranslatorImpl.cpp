#include "TranslatorImpl.h"

namespace ufrontend {

UnknownFrontendTranslatorImpl::UnknownFrontendTranslatorImpl(
    uir::Context &C,
    const std::string &BinaryFile,
    const std::string &SymbolFile) :
    mContext(C), mBinaryFile(BinaryFile), mSymbolFile(SymbolFile), mCapstoneHandle(0), mCurPtrBegin(0), mCurPtrEnd(0)
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
    mCurPtrBegin = Ptr;
}

// Set the end of current pointer
void
UnknownFrontendTranslatorImpl::setCurPtrEnd(uint64_t Ptr)
{
    mCurPtrEnd = Ptr;
}

} // namespace ufrontend

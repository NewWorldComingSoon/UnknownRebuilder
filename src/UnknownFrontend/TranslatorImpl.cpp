#include "TranslatorImpl.h"

namespace ufrontend {

UnknownFrontendTranslatorImpl::UnknownFrontendTranslatorImpl(
    uir::Context &C,
    const std::string &BinaryFile,
    const std::string &SymbolFile) :
    mContext(C), mBinaryFile(BinaryFile), mSymbolFile(SymbolFile), mCapstoneHandle(0)
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

} // namespace ufrontend

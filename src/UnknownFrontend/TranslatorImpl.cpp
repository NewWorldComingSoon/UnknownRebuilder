#include "TranslatorImpl.h"

namespace ufrontend {

UnknownFrontendTranslatorImpl::UnknownFrontendTranslatorImpl(
    uir::Context &C,
    const std::string &BinaryFile,
    const std::string &SymbolFile) :
    mContext(C), mBinaryFile(BinaryFile), mSymbolFile(SymbolFile)
{
    //
}

UnknownFrontendTranslatorImpl::~UnknownFrontendTranslatorImpl()
{
    //
}

} // namespace ufrontend

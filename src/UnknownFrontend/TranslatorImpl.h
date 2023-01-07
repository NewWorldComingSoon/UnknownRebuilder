#pragma once
#include <UnknownFrontend/UnknownFrontend.h>

namespace ufrontend {

class UnknownFrontendTranslatorImpl : public UnknownFrontendTranslator
{
public:
    UnknownFrontendTranslatorImpl(uir::Context &C, const std::string &BinaryFile, const std::string &SymbolFile);
    virtual ~UnknownFrontendTranslatorImpl();
};

} // namespace ufrontend

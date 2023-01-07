#pragma once
#include <TranslatorImpl.h>

namespace ufrontend {

class UnknownFrontendTranslatorImplX86 : public UnknownFrontendTranslatorImpl
{
public:
    UnknownFrontendTranslatorImplX86(uir::Context &C, const std::string &BinaryFile, const std::string &SymbolFile);
    virtual ~UnknownFrontendTranslatorImplX86();

protected:
    // Virtual functions
    virtual void openCapstoneHandle() override;
    virtual void closeCapstoneHandle() override;
};

} // namespace ufrontend

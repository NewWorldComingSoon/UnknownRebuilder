#pragma once
#include <TranslatorImpl.h>

namespace ufrontend {

class UnknownFrontendTranslatorImplARM : public UnknownFrontendTranslatorImpl
{
public:
    UnknownFrontendTranslatorImplARM(uir::Context &C, const std::string &BinaryFile, const std::string &SymbolFile);
    virtual ~UnknownFrontendTranslatorImplARM();

protected:
    // Virtual functions
    virtual void openCapstoneHandle() override;
    virtual void closeCapstoneHandle() override;
    virtual std::unique_ptr<uir::Module> translateBinary() override;
};

} // namespace ufrontend

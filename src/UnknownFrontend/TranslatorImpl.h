#pragma once
#include <capstone/capstone.h>

#include <UnknownFrontend/UnknownFrontend.h>

namespace ufrontend {

class UnknownFrontendTranslatorImpl : public UnknownFrontendTranslator
{
protected:
    uir::Context &mContext;
    std::string mBinaryFile;
    std::string mSymbolFile;

protected:
    csh mCapstoneHandle;

public:
    UnknownFrontendTranslatorImpl(uir::Context &C, const std::string &BinaryFile, const std::string &SymbolFile);
    virtual ~UnknownFrontendTranslatorImpl();

protected:
    // Capstone
    virtual void openCapstoneHandle() = 0;
    virtual void closeCapstoneHandle() = 0;

public:
    // Translate
    virtual std::unique_ptr<uir::Module> translateBinary() = 0;

public:
    // Get/Set
    // Get the context of this translator
    uir::Context &getContext() const;

    // Get the capstone handle
    csh getCapstoneHandle() const;

    // Set the capstone handle
    void setCapstoneHandle(csh CapstoneHandle);
};

} // namespace ufrontend

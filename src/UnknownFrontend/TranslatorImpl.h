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

protected:
    // Symbol Parser
    virtual void initSymbolParser() = 0;

protected:
    // Binary
    virtual void initBinary() = 0;

public:
    // Translate
    // Translate the given binary into UnknownIR
    virtual std::unique_ptr<uir::Module> translateBinary() = 0;

    // Translate one instruction into UnknownIR
    virtual bool translateOneInstruction(const uint8_t *Bytes, size_t Size, uint64_t Address, uir::BasicBlock *BB) = 0;
    virtual bool translateOneInstruction(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB) = 0;

public:
    // Get/Set
    // Get the context of this translator
    uir::Context &getContext() const;

    // Get the Binary File
    const std::string &getBinaryFile() const;

    // Get the Symbol File
    const std::string &getSymbolFile() const;

    // Get the capstone handle
    csh getCapstoneHandle() const;

    // Set the capstone handle
    void setCapstoneHandle(csh CapstoneHandle);
};

} // namespace ufrontend

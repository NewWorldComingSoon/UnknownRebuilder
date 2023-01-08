#pragma once
#include <TranslatorImpl.h>

namespace ufrontend {

class UnknownFrontendTranslatorImplARM : public UnknownFrontendTranslatorImpl
{
public:
    UnknownFrontendTranslatorImplARM(uir::Context &C, const std::string &BinaryFile, const std::string &SymbolFile);
    virtual ~UnknownFrontendTranslatorImplARM();

protected:
    // Capstone
    virtual void openCapstoneHandle() override;
    virtual void closeCapstoneHandle() override;

protected:
    // Symbol Parser
    virtual void initSymbolParser() override;

protected:
    // Binary
    virtual void initBinary() override;

public:
    // Translate the given binary into UnknownIR
    virtual std::unique_ptr<uir::Module> translateBinary() override;

    // Translate one instruction into UnknownIR
    virtual bool translateOneInst(const uint8_t *Bytes, size_t Size, uint64_t Address, uir::BasicBlock *BB) override;
    virtual bool translateOneInst(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB) override;
};

} // namespace ufrontend

#pragma once

#include <LIEF/PE.hpp>

#include <UnknownUtils/unknown/Symbol/SymbolParser.h>

#include <TranslatorImpl.h>

namespace ufrontend {

class UnknownFrontendTranslatorImplX86 : public UnknownFrontendTranslatorImpl
{
private:
    std::unique_ptr<unknown::SymbolParser> mSymbolParser;
    std::unique_ptr<LIEF::PE::Binary> mBinary;

public:
    UnknownFrontendTranslatorImplX86(uir::Context &C, const std::string &BinaryFile, const std::string &SymbolFile);
    virtual ~UnknownFrontendTranslatorImplX86();

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
    virtual bool
    translateOneInstruction(const uint8_t *Bytes, size_t Size, uint64_t Address, uir::BasicBlock *BB) override;
    virtual bool translateOneInstruction(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB) override;
};

} // namespace ufrontend

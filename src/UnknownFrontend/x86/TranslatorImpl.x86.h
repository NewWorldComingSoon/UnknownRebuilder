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

protected:
    // x86-specific pointer
    const uint32_t getStackPointerRegister() const;
    const unknown::StringRef getStackPointerRegisterName() const;

    const uint32_t getBasePointerRegister() const;
    const unknown::StringRef getBasePointerRegisterName() const;

public:
    // Translate the given binary into UnknownIR
    virtual std::unique_ptr<uir::Module> translateBinary(const std::string &ModuleName) override;

    // Translate one instruction into UnknownIR
    virtual bool
    translateOneInstruction(const uint8_t *Bytes, size_t Size, uint64_t Address, uir::BasicBlock *BB) override;
    virtual bool translateOneInstruction(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB) override;

    // Translate one BasicBlock into UnknownIR
    virtual uir::BasicBlock *translateOneBasicBlock(const std::string &BlockName, uint64_t Address) override;

    // Translate one Function into UnknownIR
    virtual uir::Function *translateOneFunction(const std::string &FunctionName, uint64_t Address) override;
};

} // namespace ufrontend

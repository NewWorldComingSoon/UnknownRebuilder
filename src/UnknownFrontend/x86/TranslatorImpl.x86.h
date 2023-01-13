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

private:
    bool mUsePDB;

public:
    UnknownFrontendTranslatorImplX86(
        uir::Context &C,
        const Platform Platform,
        const std::string &BinaryFile,
        const std::string &SymbolFile);
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
    // Translate
    // Init the instruction translator
    virtual void initTranslateInstruction() override;

    // Translate the given binary into UnknownIR
    virtual std::unique_ptr<uir::Module> translateBinary(const std::string &ModuleName) override;

    // Translate one instruction into UnknownIR
    virtual bool
    translateOneInstruction(const uint8_t *Bytes, size_t Size, uint64_t Address, uir::BasicBlock *BB) override;
    virtual bool
    translateOneInstruction(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB, bool &IsBlockTerminatorInsn)
        override;

    // Translate one BasicBlock into UnknownIR
    virtual uir::BasicBlock *
    translateOneBasicBlock(const std::string &BlockName, uint64_t Address, uint64_t MaxAddress) override;

    // Translate one function into UnknownIR
    virtual bool
    translateOneFunction(const std::string &FunctionName, uint64_t Address, size_t Size, uir::Function *F) override;
    virtual bool translateOneFunction(const unknown::SymbolParser::FunctionSymbol &FunctionSymbol, uir::Function *F);
    virtual bool translateOneFunction(uir::Function *F);

protected:
    // Get/Set
    // We use pdb?
    const bool hasUsePDB() const;

    // We use pdb?
    void setUsePDB(bool HasUsePDB);

protected:
    // Register
    // Get the register name by register id
    virtual std::string getRegisterName(uint32_t RegID) override;

    // Get the register id by register name
    virtual uint32_t getRegisterID(const std::string &RegName) override;

    // Get the register parent id by register id
    virtual uint32_t getRegisterParentID(uint32_t RegID) override;

    // Get the register type bits by register id
    virtual uint32_t getRegisterTypeBits(uint32_t RegID) override;

    // Get carry register
    virtual uint32_t getCarryRegister() override;

protected:
    // Attributes
    // Update function attributes
    virtual void UpdateFunctionAttributes(uir::Function *F) override;
    virtual void
    UpdateFunctionAttributes(const unknown::SymbolParser::FunctionSymbol &FunctionSymbol, uir::Function *F);
    virtual void UpdateFunctionAttributesForSEH(uir::Function *F);
    virtual void UpdateFunctionAttributesForCXXEH(uir::Function *F);

    // Update BasicBlock attributes
    virtual void UpdateBasicBlockAttributes(uir::BasicBlock *BB) override;

protected:
    // x86 instruction translation methods
    // Ret
    bool translateRetInstruction(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB);

    // Jcc
    bool translateJccInstruction(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB);

    struct InstructionInfo
    {
        decltype(&translateRetInstruction) TranslateInstruction;
        bool IsBlockTerminatorInsn;
    };
    std::unordered_map<uint32_t, InstructionInfo> mX86InstructionTranslatorMap;
};

} // namespace ufrontend

#pragma once
#include <TranslatorImpl.h>

namespace ufrontend {

class UnknownFrontendTranslatorImplARM : public UnknownFrontendTranslatorImpl
{
public:
    UnknownFrontendTranslatorImplARM(
        uir::Context &C,
        const Platform Platform,
        const std::string &BinaryFile,
        const std::string &SymbolFile);
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

protected:
    // Register
    // Get the register name by register id
    virtual std::string getRegisterName(uint32_t RegID) override;

    // Get the register id by register name
    virtual uint32_t getRegisterID(const std::string &RegName) override;

    // Get carry register
    virtual uint32_t getCarryRegister() override;

protected:
    // Attributes
    // Update function attributes
    virtual void UpdateFunctionAttributes(uir::Function *F) override;

    // Update BasicBlock attributes
    virtual void UpdateBasicBlockAttributes(uir::BasicBlock *BB) override;
};

} // namespace ufrontend

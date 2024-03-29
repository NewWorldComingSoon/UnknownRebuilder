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
        const std::string &SymbolFile,
        const std::string &ConfigFile,
        bool AnalyzeAllFunctions);
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

protected:
    // Translate
    // Init the instruction translator
    virtual void initTranslateInstruction() override;

public:
    // Translate
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
    virtual std::string getRegisterName(uint32_t RegID) const override;

    // Get the virtual register name by register id
    virtual std::string getVirtualRegisterName(uint32_t RegID) const override;

    // Get the register id by register name
    virtual uint32_t getRegisterID(const std::string &RegName) const override;

    // Get the register parent id by register id
    virtual uint32_t getRegisterParentID(uint32_t RegID) const override;

    // Get the register type bits by register id
    virtual uint32_t getRegisterTypeBits(uint32_t RegID) const override;

    // Get the register type by register id
    virtual const uir::Type *getRegisterType(uint32_t RegID) const override;

    // Get the virtual register id by register id
    virtual uint32_t getVirtualRegisterID(uint32_t RegID) const override;

    // Is the register type low 8 bits?
    virtual bool IsRegisterTypeLow8Bits(uint32_t RegID) const override;

    // Is the register type high 8 bits?
    virtual bool IsRegisterTypeHigh8Bits(uint32_t RegID) const override;

    // Get carry register
    virtual uint32_t getCarryRegister() const override;

    // Load register
    virtual std::optional<uir::Value *> loadRegister(uint32_t RegID, uint64_t Address, uir::BasicBlock *BB) override;

    // Store register
    virtual void storeRegister(const VirtualRegisterInfo &VRegInfo, uint64_t Address, uir::BasicBlock *BB) override;

    // Get register ptr
    virtual std::optional<uir::Value *> getRegisterPtr(uint32_t RegID) override;

    // Get parent register ptr
    virtual std::optional<uir::Value *> getParentRegisterPtr(uint32_t RegID) override;

protected:
    // Attributes
    // Update function attributes
    virtual void UpdateFunctionAttributes(uir::Function *F) override;

    // Update function context
    virtual void UpdateFunctionContext(uir::Function *F) override;

    // Update BasicBlock attributes
    virtual void UpdateBasicBlockAttributes(uir::BasicBlock *BB) override;
};

} // namespace ufrontend

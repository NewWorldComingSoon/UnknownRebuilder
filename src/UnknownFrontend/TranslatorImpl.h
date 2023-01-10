#pragma once
#include <capstone/capstone.h>

#include <UnknownFrontend/UnknownFrontend.h>

namespace ufrontend {

class UnknownFrontendTranslatorImpl : public UnknownFrontendTranslator
{
protected:
    Platform mPlatform;
    uir::Context &mContext;
    std::string mBinaryFile;
    std::string mSymbolFile;

protected:
    csh mCapstoneHandle;

protected:
    uint64_t mCurPtrBegin;
    uint64_t mCurPtrEnd;

protected:
    uir::Function *mCurFunction;

public:
    UnknownFrontendTranslatorImpl(
        uir::Context &C,
        const Platform Platform,
        const std::string &BinaryFile,
        const std::string &SymbolFile);
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
    virtual std::unique_ptr<uir::Module> translateBinary(const std::string &ModuleName) override { return {}; }

    // Translate one instruction into UnknownIR
    virtual bool
    translateOneInstruction(const uint8_t *Bytes, size_t Size, uint64_t Address, uir::BasicBlock *BB) override
    {
        return false;
    }
    virtual bool translateOneInstruction(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB) = 0;

    // Translate one BasicBlock into UnknownIR
    virtual uir::BasicBlock *translateOneBasicBlock(const std::string &BlockName, uint64_t Address) override
    {
        return nullptr;
    }

    // Translate one function into UnknownIR
    virtual bool
    translateOneFunction(const std::string &FunctionName, uint64_t Address, size_t Size, uir::Function *F) override
    {
        return false;
    }

public:
    // Get/Set
    // Get the capstone handle
    csh getCapstoneHandle() const;

    // Set the capstone handle
    void setCapstoneHandle(csh CapstoneHandle);

    // Get the context of this translator
    virtual uir::Context &getContext() const override;

    // Get the Binary File
    virtual const std::string &getBinaryFile() const override;

    // Get the Symbol File
    virtual const std::string &getSymbolFile() const override;

    // Get the begin of current pointer
    virtual const uint64_t getCurPtrBegin() const override;

    // Get the end of current pointer
    virtual const uint64_t getCurPtrEnd() const override;

    // Set the begin of current pointer
    virtual void setCurPtrBegin(uint64_t Ptr) override;

    // Set the end of current pointer
    virtual void setCurPtrEnd(uint64_t Ptr) override;

    // Get the current function
    virtual const uir::Function *getCurFunction() const override;

    // Set the current function
    virtual void setCurFunction(uir::Function *Function) override;

    // Get the platform
    virtual const Platform getPlatform() const override;

    // Set the platform
    virtual void setPlatform(Platform Plat) override;

protected:
    // Register
    // Get carry register.
    virtual uint32_t getCarryRegister() = 0;

protected:
    // Attributes
    // Update function attributes
    virtual void UpdateFunctionAttributes(uir::Function *F) = 0;

    // Update BasicBlock attributes
    virtual void UpdateBasicBlockAttributes(uir::BasicBlock *BB) = 0;
};

} // namespace ufrontend

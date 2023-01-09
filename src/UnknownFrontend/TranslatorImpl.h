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

protected:
    uint64_t mCurPtrBegin;
    uint64_t mCurPtrEnd;

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

    // Translate one Function into UnknownIR
    virtual uir::Function *translateOneFunction(const std::string &FunctionName, uint64_t Address) override
    {
        return nullptr;
    }

public:
    // Get/Set
    // Get the context of this translator
    virtual uir::Context &getContext() const override;

    // Get the Binary File
    virtual const std::string &getBinaryFile() const override;

    // Get the Symbol File
    virtual const std::string &getSymbolFile() const override;

    // Get the capstone handle
    csh getCapstoneHandle() const;

    // Set the capstone handle
    void setCapstoneHandle(csh CapstoneHandle);

    // Get the begin of current pointer
    virtual const uint64_t getCurPtrBegin() const override;

    // Get the end of current pointer
    virtual const uint64_t getCurPtrEnd() const override;

    // Set the begin of current pointer
    virtual void setCurPtrBegin(uint64_t Ptr) override;

    // Set the end of current pointer
    virtual void setCurPtrEnd(uint64_t Ptr) override;
};

} // namespace ufrontend

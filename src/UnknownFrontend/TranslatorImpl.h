#pragma once
#include <capstone/capstone.h>

#include <UnknownUtils/unknown/Target/Target.h>

#include <UnknownFrontend/UnknownFrontend.h>

#include "ConfigReader.h"

namespace ufrontend {

class UnknownFrontendTranslatorImpl : public UnknownFrontendTranslator
{
protected:
    Platform mPlatform;
    uir::Context &mContext;
    std::string mBinaryFile;
    std::string mSymbolFile;
    std::string mConfigFile;
    bool mEnableAnalyzeAllFunctions;

protected:
    csh mCapstoneHandle;

protected:
    uint64_t mCurPtrBegin;
    uint64_t mCurPtrEnd;

protected:
    uir::Function *mCurFunction;

protected:
    std::unique_ptr<unknown::Target> mTarget;
    std::unique_ptr<ufrontend::ConfigReader> mConfigReader;

public:
    UnknownFrontendTranslatorImpl(
        uir::Context &C,
        const Platform Platform,
        const std::string &BinaryFile,
        const std::string &SymbolFile,
        const std::string &ConfigFile,
        bool AnalyzeAllFunctions);
    virtual ~UnknownFrontendTranslatorImpl();

public:
    // Init
    // Init the translator
    virtual void initTranslator() override;

protected:
    // Capstone
    virtual void openCapstoneHandle() {}
    virtual void closeCapstoneHandle() {}

protected:
    // Symbol Parser
    virtual void initSymbolParser() {}

protected:
    // Binary
    virtual void initBinary() {}

protected:
    // Config
    virtual void initConfig();

protected:
    // Translate
    // Init the instruction translator
    virtual void initTranslateInstruction() {}

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
    virtual bool translateOneInstruction(
        const cs_insn *Insn,
        uint64_t Address,
        uir::BasicBlock *BB,
        bool &IsBlockTerminatorInsn) = 0;

    // Translate one BasicBlock into UnknownIR
    virtual uir::BasicBlock *
    translateOneBasicBlock(const std::string &BlockName, uint64_t Address, uint64_t MaxAddress) override
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

    // Get the Config File
    virtual const std::string &getConfigFile() const override;

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

    // Get EnableAnalyzeAllFunctions
    virtual const bool getEnableAnalyzeAllFunctions() const override;

    // Set EnableAnalyzeAllFunctions
    virtual void setEnableAnalyzeAllFunctions(bool Set) override;

protected:
    // Register
    // Get the register name by register id
    virtual std::string getRegisterName(uint32_t RegID) const = 0;

    // Get the virtual register name by register id
    virtual std::string getVirtualRegisterName(uint32_t RegID) const = 0;

    // Get the register id by register name
    virtual uint32_t getRegisterID(const std::string &RegName) const = 0;

    // Get the register parent id by register id
    virtual uint32_t getRegisterParentID(uint32_t RegID) const = 0;

    // Get the register type bits by register id
    virtual uint32_t getRegisterTypeBits(uint32_t RegID) const = 0;

    // Get the register type  by register id
    virtual const uir::Type *getRegisterType(uint32_t RegID) const = 0;

    // Get the virtual register id by register id
    virtual uint32_t getVirtualRegisterID(uint32_t RegID) const = 0;

    // Is the register type low 8 bits?
    virtual bool IsRegisterTypeLow8Bits(uint32_t RegID) const = 0;

    // Is the register type high 8 bits?
    virtual bool IsRegisterTypeHigh8Bits(uint32_t RegID) const = 0;

    // Get carry register
    virtual uint32_t getCarryRegister() const = 0;

    // Load register
    virtual uir::Value *loadRegister(const cs_insn *Insn, uir::BasicBlock *BB) = 0;

protected:
    // Attributes
    // Update function attributes
    virtual void UpdateFunctionAttributes(uir::Function *F) = 0;

    // Update function context
    virtual void UpdateFunctionContext(uir::Function *F) = 0;

    // Update BasicBlock attributes
    virtual void UpdateBasicBlockAttributes(uir::BasicBlock *BB) = 0;
};

} // namespace ufrontend

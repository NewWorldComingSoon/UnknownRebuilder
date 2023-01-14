#pragma once
#include <cassert>
#include <cstdint>
#include <memory>
#include <string>
#include <iostream>
#include <map>
#include <unordered_map>
#include <vector>

#include <UnknownIR/UnknownIR.h>

namespace ufrontend {

class UnknownFrontendTranslator
{
public:
    enum class Platform : uint32_t
    {
        WINDOWS_X86,
        WINDOWS_ARM,

        LINUX_X86,
        LINUX_ARM,

        ANDROID_X86,
        ANDROID_ARM,

        OSX_X86,
        OSX_ARM,

        UNKNOWN
    };

public:
    UnknownFrontendTranslator() = default;
    virtual ~UnknownFrontendTranslator() = default;

public:
    // Translate
    // Translate the given binary into UnknownIR
    virtual std::unique_ptr<uir::Module> translateBinary(const std::string &ModuleName) = 0;

    // Translate one instruction into UnknownIR
    virtual bool translateOneInstruction(const uint8_t *Bytes, size_t Size, uint64_t Address, uir::BasicBlock *BB) = 0;

    // Translate one BasicBlock into UnknownIR
    virtual uir::BasicBlock *
    translateOneBasicBlock(const std::string &BlockName, uint64_t Address, uint64_t MaxAddress) = 0;

    // Translate one function into UnknownIR
    virtual bool
    translateOneFunction(const std::string &FunctionName, uint64_t Address, size_t Size, uir::Function *F) = 0;

public:
    // Get/Set
    // Get the context of this translator
    virtual uir::Context &getContext() const = 0;

    // Get the Binary File
    virtual const std::string &getBinaryFile() const = 0;

    // Get the Symbol File
    virtual const std::string &getSymbolFile() const = 0;

    // Get the Config File
    virtual const std::string &getConfigFile() const = 0;

    // Get the begin of current pointer
    virtual const uint64_t getCurPtrBegin() const = 0;

    // Get the end of current pointer
    virtual const uint64_t getCurPtrEnd() const = 0;

    // Set the begin of current pointer
    virtual void setCurPtrBegin(uint64_t Ptr) = 0;

    // Set the end of current pointer
    virtual void setCurPtrEnd(uint64_t Ptr) = 0;

    // Get the current function
    virtual const uir::Function *getCurFunction() const = 0;

    // Set the current function
    virtual void setCurFunction(uir::Function *Function) = 0;

    // Get the platform
    virtual const Platform getPlatform() const = 0;

    // Set the platform
    virtual void setPlatform(Platform Plat) = 0;

public:
    // Static
    static std::unique_ptr<UnknownFrontendTranslator> createTranslator(
        uir::Context &C,
        const std::string &BinaryFile,
        const std::string &SymbolFile,
        const std::string &ConfigFile,
        const Platform Platform = Platform::WINDOWS_X86);
};

} // namespace ufrontend

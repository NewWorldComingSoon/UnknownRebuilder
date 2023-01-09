#pragma once
#include <cassert>
#include <cstdint>
#include <memory>
#include <string>
#include <iostream>

#include <UnknownIR/UnknownIR.h>

namespace ufrontend {

class UnknownFrontendTranslator
{
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
    virtual uir::BasicBlock *translateOneBasicBlock(const std::string &BlockName, uint64_t Address) = 0;

    // Translate one Function into UnknownIR
    virtual uir::Function *translateOneFunction(const std::string &FunctionName, uint64_t Address) = 0;

public:
    // Get/Set
    // Get the context of this translator
    virtual uir::Context &getContext() const = 0;

    // Get the Binary File
    virtual const std::string &getBinaryFile() const = 0;

    // Get the Symbol File
    virtual const std::string &getSymbolFile() const = 0;

    // Get the begin of current pointer
    virtual const uint64_t getCurPtrBegin() const = 0;

    // Get the end of current pointer
    virtual const uint64_t getCurPtrEnd() const = 0;

    // Set the begin of current pointer
    virtual void setCurPtrBegin(uint64_t Ptr) = 0;

    // Set the end of current pointer
    virtual void setCurPtrEnd(uint64_t Ptr) = 0;

public:
    // Static
    static std::unique_ptr<UnknownFrontendTranslator>
    createArch(uir::Context &C, const std::string &BinaryFile, const std::string &SymbolFile);
};

} // namespace ufrontend

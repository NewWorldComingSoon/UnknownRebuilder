#include "TranslatorImpl.arm.h"

namespace ufrontend {

UnknownFrontendTranslatorImplARM::UnknownFrontendTranslatorImplARM(
    uir::Context &C,
    const Platform Platform,
    const std::string &BinaryFile,
    const std::string &SymbolFile) :
    UnknownFrontendTranslatorImpl(C, Platform, BinaryFile, SymbolFile)
{
    //
}

UnknownFrontendTranslatorImplARM::~UnknownFrontendTranslatorImplARM()
{
    //
}

////////////////////////////////////////////////////////////
// Capstone
void
UnknownFrontendTranslatorImplARM::openCapstoneHandle()
{
    // TODO
}

void
UnknownFrontendTranslatorImplARM::closeCapstoneHandle()
{
    // TODO
}

////////////////////////////////////////////////////////////
// Symbol Parser
void
UnknownFrontendTranslatorImplARM::initSymbolParser()
{
    // TODO
}

////////////////////////////////////////////////////////////
// Binary
void
UnknownFrontendTranslatorImplARM::initBinary()
{
    // TODO
}

////////////////////////////////////////////////////////////
// Translate
// Translate the given binary into UnknownIR
std::unique_ptr<uir::Module>
UnknownFrontendTranslatorImplARM::translateBinary(const std::string &ModuleName)
{
    // TODO
    return {};
}

// Translate one instruction into UnknownIR
bool
UnknownFrontendTranslatorImplARM::translateOneInstruction(
    const uint8_t *Bytes,
    size_t Size,
    uint64_t Address,
    uir::BasicBlock *BB)
{
    // TODO
    return true;
}

bool
UnknownFrontendTranslatorImplARM::translateOneInstruction(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB)
{
    // TODO
    return true;
}

// Translate one BasicBlock into UnknownIR
uir::BasicBlock *
UnknownFrontendTranslatorImplARM::translateOneBasicBlock(const std::string &BlockName, uint64_t Address)
{
    // TODO
    return nullptr;
}

// Translate one function into UnknownIR
bool
UnknownFrontendTranslatorImplARM::translateOneFunction(
    const std::string &FunctionName,
    uint64_t Address,
    size_t Size,
    uir::Function *F)
{
    assert(F);

    // TODO
    return false;
}

////////////////////////////////////////////////////////////
// Attributes
// Update function attributes
void
UnknownFrontendTranslatorImplARM::UpdateFunctionAttributes(uir::Function *F)
{
    // TODO
}

} // namespace ufrontend

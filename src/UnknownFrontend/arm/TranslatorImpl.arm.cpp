#include "TranslatorImpl.arm.h"

namespace ufrontend {

UnknownFrontendTranslatorImplARM::UnknownFrontendTranslatorImplARM(
    uir::Context &C,
    const std::string &BinaryFile,
    const std::string &SymbolFile) :
    UnknownFrontendTranslatorImpl(C, BinaryFile, SymbolFile)
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
UnknownFrontendTranslatorImplARM::translateBinary()
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

// Translate one Function into UnknownIR
uir::Function *
UnknownFrontendTranslatorImplARM::translateOneFunction(const std::string &FunctionName, uint64_t Address)
{
    // TODO
    return nullptr;
}

} // namespace ufrontend

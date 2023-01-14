#include "TranslatorImpl.arm.h"

namespace ufrontend {

UnknownFrontendTranslatorImplARM::UnknownFrontendTranslatorImplARM(
    uir::Context &C,
    const Platform Platform,
    const std::string &BinaryFile,
    const std::string &SymbolFile,
    const std::string &ConfigFile,
    bool OutputAllFunctions) :
    UnknownFrontendTranslatorImpl(C, Platform, BinaryFile, SymbolFile, ConfigFile, OutputAllFunctions)
{
    mTarget = unknown::CreateTargetForARM(C.getModeBits());

    openCapstoneHandle();
    initSymbolParser();
    initBinary();
    initTranslateInstruction();
}

UnknownFrontendTranslatorImplARM::~UnknownFrontendTranslatorImplARM()
{
    closeCapstoneHandle();
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
// Init the instruction translator
void
UnknownFrontendTranslatorImplARM::initTranslateInstruction()
{
}

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
UnknownFrontendTranslatorImplARM::translateOneInstruction(
    const cs_insn *Insn,
    uint64_t Address,
    uir::BasicBlock *BB,
    bool &IsBlockTerminatorInsn)
{
    // TODO
    return true;
}

// Translate one BasicBlock into UnknownIR
uir::BasicBlock *
UnknownFrontendTranslatorImplARM::translateOneBasicBlock(
    const std::string &BlockName,
    uint64_t Address,
    uint64_t MaxAddress)
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
// Register
// Get the register name by register id
std::string
UnknownFrontendTranslatorImplARM::getRegisterName(uint32_t RegID)
{
    return mTarget->getRegisterName(RegID);
}

// Get the register id by register name
uint32_t
UnknownFrontendTranslatorImplARM::getRegisterID(const std::string &RegName)
{
    return mTarget->getRegisterID(RegName);
}

// Get the register parent id by register id
uint32_t
UnknownFrontendTranslatorImplARM::getRegisterParentID(uint32_t RegID)
{
    return mTarget->getRegisterParentID(RegID);
}

// Get the register type bits by register id
uint32_t
UnknownFrontendTranslatorImplARM::getRegisterTypeBits(uint32_t RegID)
{
    return mTarget->getRegisterTypeBits(RegID);
}

// Get carry register
uint32_t
UnknownFrontendTranslatorImplARM::getCarryRegister()
{
    return mTarget->getCarryRegister();
}

////////////////////////////////////////////////////////////
// Attributes
// Update function attributes
void
UnknownFrontendTranslatorImplARM::UpdateFunctionAttributes(uir::Function *F)
{
    assert(F);

    // TODO
}

// Update BasicBlock attributes
void
UnknownFrontendTranslatorImplARM::UpdateBasicBlockAttributes(uir::BasicBlock *BB)
{
    assert(BB);

    // TODO
}

} // namespace ufrontend

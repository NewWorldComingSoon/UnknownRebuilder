#include "TranslatorImpl.arm.h"

namespace ufrontend {

UnknownFrontendTranslatorImplARM::UnknownFrontendTranslatorImplARM(
    uir::Context &C,
    const Platform Platform,
    const std::string &BinaryFile,
    const std::string &SymbolFile,
    const std::string &ConfigFile,
    bool AnalyzeAllFunctions) :
    UnknownFrontendTranslatorImpl(C, Platform, BinaryFile, SymbolFile, ConfigFile, AnalyzeAllFunctions)
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
UnknownFrontendTranslatorImplARM::getRegisterName(uint32_t RegID) const
{
    return mTarget->getRegisterName(RegID);
}

// Get the virtual register name by register id
std::string
UnknownFrontendTranslatorImplARM::getVirtualRegisterName(uint32_t RegID) const
{
    // We simply use register name as virtual register name
    return getRegisterName(RegID);
}

// Get the register id by register name
uint32_t
UnknownFrontendTranslatorImplARM::getRegisterID(const std::string &RegName) const
{
    return mTarget->getRegisterID(RegName);
}

// Get the register parent id by register id
uint32_t
UnknownFrontendTranslatorImplARM::getRegisterParentID(uint32_t RegID) const
{
    return mTarget->getRegisterParentID(RegID);
}

// Get the register type bits by register id
uint32_t
UnknownFrontendTranslatorImplARM::getRegisterTypeBits(uint32_t RegID) const
{
    return mTarget->getRegisterTypeBits(RegID);
}

// Get the register type by register id
const uir::Type *
UnknownFrontendTranslatorImplARM::getRegisterType(uint32_t RegID) const
{
    auto Bits = getRegisterTypeBits(RegID);
    return uir::Type::getIntNTy(getContext(), Bits);
}

// Get the virtual register id by register id
uint32_t
UnknownFrontendTranslatorImplARM::getVirtualRegisterID(uint32_t RegID) const
{
    // We simply use the parent register id as the virtual register id
    return getRegisterParentID(RegID);
}

// Is the register type low 8 bits?
bool
UnknownFrontendTranslatorImplARM::IsRegisterTypeLow8Bits(uint32_t RegID) const
{
    return mTarget->IsRegisterTypeLow8Bits(RegID);
}

// Is the register type high 8 bits?
bool
UnknownFrontendTranslatorImplARM::IsRegisterTypeHigh8Bits(uint32_t RegID) const
{
    return mTarget->IsRegisterTypeHigh8Bits(RegID);
}

// Get carry register
uint32_t
UnknownFrontendTranslatorImplARM::getCarryRegister() const
{
    return mTarget->getCarryRegister();
}

// Load register
uir::Value *
UnknownFrontendTranslatorImplARM::loadRegister(const cs_insn *Insn, uir::BasicBlock *BB)
{
    // TODO
    return nullptr;
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

// Update function context
void
UnknownFrontendTranslatorImplARM::UpdateFunctionContext(uir::Function *F)
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

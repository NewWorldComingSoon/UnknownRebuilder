#include "TranslatorImpl.x86.h"
#include "Error.h"

#include <unknown/ADT/ScopeExit.h>

namespace ufrontend {

UnknownFrontendTranslatorImplX86::UnknownFrontendTranslatorImplX86(
    uir::Context &C,
    const Platform Platform,
    const std::string &BinaryFile,
    const std::string &SymbolFile,
    const std::string &ConfigFile,
    bool AnalyzeAllFunctions) :
    UnknownFrontendTranslatorImpl(C, Platform, BinaryFile, SymbolFile, ConfigFile, AnalyzeAllFunctions), mUsePDB(false)
{
    //
}

UnknownFrontendTranslatorImplX86::~UnknownFrontendTranslatorImplX86()
{
    closeCapstoneHandle();
}

////////////////////////////////////////////////////////////
// Capstone
void
UnknownFrontendTranslatorImplX86::openCapstoneHandle()
{
    cs_mode Mode = cs_mode::CS_MODE_32;
    if (getContext().getModeBits() == 64)
    {
        Mode = cs_mode::CS_MODE_64;
    }

    csh CapstoneHandle;
    if (cs_open(cs_arch::CS_ARCH_X86, Mode, &CapstoneHandle) != CS_ERR_OK)
    {
        std::cerr << UFRONTEND_ERROR_PREFIX + std::string(cs_strerror(cs_errno(CapstoneHandle))) << std::endl;
        return;
    }

    cs_option(CapstoneHandle, CS_OPT_DETAIL, CS_OPT_ON);

    mCapstoneHandle = CapstoneHandle;
}

void
UnknownFrontendTranslatorImplX86::closeCapstoneHandle()
{
    auto CapstoneHandle = mCapstoneHandle;
    if (CapstoneHandle != 0)
    {
        if (cs_close(&CapstoneHandle) != CS_ERR_OK)
        {
            std::cerr << UFRONTEND_ERROR_PREFIX + std::string(cs_strerror(cs_errno(CapstoneHandle))) << std::endl;
            return;
        }

        mCapstoneHandle = 0;
    }
}

////////////////////////////////////////////////////////////
// Symbol Parser
void
UnknownFrontendTranslatorImplX86::initSymbolParser()
{
    assert(!getSymbolFile().empty());

    bool UsePDB = false;
    if (getSymbolFile().rfind(".pdb") != std::string::npos)
    {
        UsePDB = true;
    }

    setUsePDB(UsePDB);

    if (!UsePDB)
    {
        if (getSymbolFile().rfind(".map") == std::string::npos)
        {
            std::cerr << UFRONTEND_ERROR_PREFIX "Symbol file is not a .map/.pdb file" << std::endl;
            std::abort();
        }
    }

    mSymbolParser = unknown::CreateSymbolParserForPE(UsePDB);
    assert(mSymbolParser);

    if (!mSymbolParser->ParseFunctionSymbols(getSymbolFile()))
    {
        std::cerr << UFRONTEND_ERROR_PREFIX "ParseFunctionSymbols failed" << std::endl;
        std::abort();
    }
}

////////////////////////////////////////////////////////////
// Binary
void
UnknownFrontendTranslatorImplX86::initBinary()
{
    assert(!getBinaryFile().empty());

    mBinary = LIEF::PE::Parser::parse(getBinaryFile());
    assert(mBinary);
}

////////////////////////////////////////////////////////////
// x86-specific pointer
const uint32_t
UnknownFrontendTranslatorImplX86::getStackPointerRegister() const
{
    return mTarget->getStackPointerRegister();
}

const unknown::StringRef
UnknownFrontendTranslatorImplX86::getStackPointerRegisterName() const
{
    return mTarget->getStackPointerRegisterName();
}

const uint32_t
UnknownFrontendTranslatorImplX86::getBasePointerRegister() const
{
    return mTarget->getBasePointerRegister();
}

const unknown::StringRef
UnknownFrontendTranslatorImplX86::getBasePointerRegisterName() const
{
    return mTarget->getBasePointerRegisterName();
}

////////////////////////////////////////////////////////////
// Translate
// Init the instruction translator
void
UnknownFrontendTranslatorImplX86::initTranslateInstruction()
{
    mX86InstructionTranslatorMap = {
        // Ret
        {X86_INS_RET, {&UnknownFrontendTranslatorImplX86::translateRetInstruction, true}},

        // Mov
        {X86_INS_MOV, {&UnknownFrontendTranslatorImplX86::translateMovInstruction, false}},

        // Push/Pop
        {X86_INS_PUSH, {&UnknownFrontendTranslatorImplX86::translatePushInstruction, false}},
        {X86_INS_POP, {&UnknownFrontendTranslatorImplX86::translatePopInstruction, false}},

        // Jcc
        {X86_INS_JAE, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JA, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JBE, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JB, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JE, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JGE, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JG, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JLE, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JL, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JNE, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JNO, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JNP, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JNS, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JO, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JP, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}},
        {X86_INS_JS, {&UnknownFrontendTranslatorImplX86::translateJccInstruction, true}}

    };
}

// Translate the given binary into UnknownIR
std::unique_ptr<uir::Module>
UnknownFrontendTranslatorImplX86::translateBinary(const std::string &ModuleName)
{
    auto Module = uir::Module::get(getContext(), ModuleName);
    assert(Module);

    for (auto &FunctionSymbol : mSymbolParser->getFunctionSymbols())
    {
        auto F = std::make_unique<uir::Function>(getContext());
        assert(F);

        // Translate the function into UnknownIR
        bool TransRes = translateOneFunction(FunctionSymbol, F.get());
        if (TransRes)
        {
            if (!F->empty())
            {
                // Insert the function into the module
                Module->insertFunction(F.release());
            }
        }
        else
        {
            std::cerr << std::format(UFRONTEND_ERROR_PREFIX "translateOneFunction: {} failed", F->getFunctionName())
                      << std::endl;
        }
    }

    return Module;
}

// Translate one instruction into UnknownIR
bool
UnknownFrontendTranslatorImplX86::translateOneInstruction(
    const uint8_t *Bytes,
    size_t Size,
    uint64_t Address,
    uir::BasicBlock *BB)
{
    assert(Bytes);
    assert(BB);

    cs_insn *Insn = nullptr;

    // Disasm
    size_t DisasmCount = cs_disasm(getCapstoneHandle(), const_cast<const uint8_t *>(Bytes), Size, Address, 1, &Insn);
    auto DeferredInsn = unknown::make_scope_exit([&Insn]() {
        if (Insn)
        {
            cs_free(Insn, 1);
            Insn = nullptr;
        }
    });

    bool DisasmRes = DisasmCount == 1;
    if (!DisasmRes)
    {
        std::cerr << std::format(UFRONTEND_ERROR_PREFIX "disasm: 0x{:X} failed", Address) << std::endl;
        return false;
    }

    bool IsTerminatorInsn = false;
    return translateOneInstruction(Insn, Address, BB, IsTerminatorInsn);
}

bool
UnknownFrontendTranslatorImplX86::translateOneInstruction(
    const cs_insn *Insn,
    uint64_t Address,
    uir::BasicBlock *BB,
    bool &IsBlockTerminatorInsn)
{
    assert(Insn);
    assert(BB);

    IsBlockTerminatorInsn = false;

    if (getCurPtrBegin() != Address)
    {
        // Set the begin of current pointer
        setCurPtrBegin(Address);
        assert(getCurPtrBegin());
    }

    if (getCurPtrEnd() == 0)
    {
        // Set the end of current pointer
        setCurPtrEnd(Address + Insn->size);
        if (getCurPtrEnd() <= getCurPtrBegin())
        {
            auto CurSection = mBinary->get_section(getCurPtrBegin());
            if (CurSection)
            {
                setCurPtrEnd(mBinary->imagebase() + CurSection->virtual_address() + CurSection->sizeof_raw_data());
            }
        }
        assert(getCurPtrEnd());
        assert(getCurPtrEnd() > getCurPtrBegin());
    }

    bool TransRes = false;

    auto ItTrans = mX86InstructionTranslatorMap.find(Insn->id);
    if (ItTrans != mX86InstructionTranslatorMap.end())
    {
        auto &TransInfo = ItTrans->second;
        IsBlockTerminatorInsn = TransInfo.IsBlockTerminatorInsn;
        TransRes = (this->*TransInfo.TranslateFunction)(Insn, BB);
    }
    else
    {
        TransRes = translateUnknownX86Instruction(Insn, BB);
    }

    return TransRes;
}

// Translate one BasicBlock into UnknownIR
uir::BasicBlock *
UnknownFrontendTranslatorImplX86::translateOneBasicBlock(
    const std::string &BlockName,
    uint64_t Address,
    uint64_t MaxAddress)
{
    assert(Address);

    if (getCurPtrBegin() != Address)
    {
        // Set the begin of current pointer
        setCurPtrBegin(Address);
        assert(getCurPtrBegin());
    }

    if (getCurPtrEnd() == 0)
    {
        // Set the end of current pointer
        setCurPtrEnd(MaxAddress);
        if (getCurPtrEnd() <= getCurPtrBegin())
        {
            auto CurSection = mBinary->get_section(getCurPtrBegin());
            if (CurSection)
            {
                setCurPtrEnd(mBinary->imagebase() + CurSection->virtual_address() + CurSection->sizeof_raw_data());
            }
        }
        assert(getCurPtrEnd());
        assert(getCurPtrEnd() > getCurPtrBegin());
    }

    auto NewBB = std::make_unique<uir::BasicBlock>(getContext(), BlockName, Address, MaxAddress);
    assert(NewBB);

    // Translate
    while (getCurPtrBegin() < getCurPtrEnd())
    {
        cs_insn *Insn = nullptr;

        uint64_t Address = getCurPtrBegin();
        uint64_t MaxAddress = getCurPtrEnd();
        size_t Size = MaxAddress - Address;

        uint8_t *Bytes = new uint8_t[Size]{};
        assert(Bytes);
        auto DeferredBytes = unknown::make_scope_exit([&Bytes]() {
            if (Bytes)
            {
                delete[] Bytes;
                Bytes = nullptr;
            }
        });

        auto Contents = mBinary->get_content_from_virtual_address(Address, Size);
        assert(!Contents.empty());
        std::copy(Contents.begin(), Contents.end(), Bytes);

        // Disasm
        size_t DisasmCount =
            cs_disasm(getCapstoneHandle(), const_cast<const uint8_t *>(Bytes), Size, Address, 1, &Insn);
        auto DeferredInsn = unknown::make_scope_exit([&Insn]() {
            if (Insn)
            {
                cs_free(Insn, 1);
                Insn = nullptr;
            }
        });

        bool DisasmRes = DisasmCount == 1;
        if (!DisasmRes)
        {
            std::cerr << std::format(UFRONTEND_ERROR_PREFIX "disasm: 0x{:X} failed", Address) << std::endl;
            break;
        }

        // Translate one instruction
        bool IsTerminatorInsn = false;
        bool TransRes = translateOneInstruction(Insn, Address, NewBB.get(), IsTerminatorInsn);
        if (!TransRes)
        {
            std::cerr << std::format(UFRONTEND_ERROR_PREFIX "translateOneInstruction: 0x{:X} failed", Address)
                      << std::endl;
            break;
        }

        // Update ptr
        setCurPtrBegin(Address + Insn->size);

        if (IsTerminatorInsn)
        {
            break;
        }
    }

    if (NewBB->empty())
    {
        NewBB.reset(nullptr);
        return nullptr;
    }

    // Update the end address of the basic block
    NewBB->setBasicBlockAddressEnd(getCurPtrBegin());

    return NewBB.release();
}

// Translate one function into UnknownIR
bool
UnknownFrontendTranslatorImplX86::translateOneFunction(
    const std::string &FunctionName,
    uint64_t Address,
    size_t Size,
    uir::Function *F)
{
    assert(Address);
    assert(F);

    // We only analyze the function that has attributes if not mEnableAnalyzeAllFunctions
    if (!mEnableAnalyzeAllFunctions && F->getFunctionAttributes().empty())
    {
        return true;
    }

    // Set the current function
    setCurFunction(F);

    // Set the begin and end of current pointer
    setCurPtrBegin(Address ? Address : F->getFunctionBeginAddress());
    setCurPtrEnd(Size ? Address + Size : F->getFunctionEndAddress());

    // Update the end pointer if it's not valid
    if (getCurPtrEnd() <= getCurPtrBegin())
    {
        auto CurSection = mBinary->get_section(getCurPtrBegin());
        if (CurSection)
        {
            setCurPtrEnd(mBinary->imagebase() + CurSection->virtual_address() + CurSection->sizeof_raw_data());
        }
    }

    assert(getCurPtrBegin());
    assert(getCurPtrEnd());
    assert(getCurPtrEnd() > getCurPtrBegin());

    while (getCurPtrBegin() < getCurPtrEnd())
    {
        // Translate a basic block
        auto BB = translateOneBasicBlock("", getCurPtrBegin(), getCurPtrEnd());
        if (BB == nullptr)
        {
            break;
        }

        // Insert a basic block into the function
        if (!BB->empty())
        {
            F->insertBasicBlock(BB);
        }

        // Update ptr
        setCurPtrBegin(BB->getBasicBlockAddressEnd());
    }

    if (F->empty())
    {
        return false;
    }

    // Update function context
    UpdateFunctionContext(F);

    return true;
}

bool
UnknownFrontendTranslatorImplX86::translateOneFunction(
    const unknown::SymbolParser::FunctionSymbol &FunctionSymbol,
    uir::Function *F)
{
    assert(F);

    // Update function attributes
    UpdateFunctionAttributes(FunctionSymbol, F);

    return translateOneFunction(F);
}

bool
UnknownFrontendTranslatorImplX86::translateOneFunction(uir::Function *F)
{
    assert(F);

    return translateOneFunction(
        F->getFunctionName(),
        F->getFunctionBeginAddress(),
        F->getFunctionEndAddress() - F->getFunctionBeginAddress(),
        F);
}

////////////////////////////////////////////////////////////
// Get/Set
// We use pdb?
const bool
UnknownFrontendTranslatorImplX86::hasUsePDB() const
{
    return mUsePDB;
}

// We use pdb?
void
UnknownFrontendTranslatorImplX86::setUsePDB(bool HasUsePDB)
{
    mUsePDB = HasUsePDB;
}

////////////////////////////////////////////////////////////
// Register
// Get the register name by register id
std::string
UnknownFrontendTranslatorImplX86::getRegisterName(uint32_t RegID) const
{
    return mTarget->getRegisterName(RegID);
}

// Get the virtual register name by register id
std::string
UnknownFrontendTranslatorImplX86::getVirtualRegisterName(uint32_t RegID) const
{
    // We simply use register name as virtual register name
    return getRegisterName(RegID);
}

// Get the register id by register name
uint32_t
UnknownFrontendTranslatorImplX86::getRegisterID(const std::string &RegName) const
{
    return mTarget->getRegisterID(RegName);
}

// Get the register parent id by register id
uint32_t
UnknownFrontendTranslatorImplX86::getRegisterParentID(uint32_t RegID) const
{
    return mTarget->getRegisterParentID(RegID);
}

// Get the register type bits by register id
uint32_t
UnknownFrontendTranslatorImplX86::getRegisterTypeBits(uint32_t RegID) const
{
    return mTarget->getRegisterTypeBits(RegID);
}

// Get the register type by register id
const uir::Type *
UnknownFrontendTranslatorImplX86::getRegisterType(uint32_t RegID) const
{
    auto Bits = getRegisterTypeBits(RegID);
    return uir::Type::getIntNTy(getContext(), Bits);
}

// Get the virtual register id by register id
uint32_t
UnknownFrontendTranslatorImplX86::getVirtualRegisterID(uint32_t RegID) const
{
    // We simply use the parent register id as the virtual register id
    return getRegisterParentID(RegID);
}

// Is the register type low 8 bits?
bool
UnknownFrontendTranslatorImplX86::IsRegisterTypeLow8Bits(uint32_t RegID) const
{
    return mTarget->IsRegisterTypeLow8Bits(RegID);
}

// Is the register type high 8 bits?
bool
UnknownFrontendTranslatorImplX86::IsRegisterTypeHigh8Bits(uint32_t RegID) const
{
    return mTarget->IsRegisterTypeHigh8Bits(RegID);
}

// Get carry register
uint32_t
UnknownFrontendTranslatorImplX86::getCarryRegister() const
{
    return mTarget->getCarryRegister();
}

// Load register
uir::Value *
UnknownFrontendTranslatorImplX86::loadRegister(const cs_insn *Insn, uir::BasicBlock *BB)
{
    assert(Insn);
    assert(BB);

    auto VRegInfo = getVirtualRegisterInfo(Insn->id);
    if (!VRegInfo)
    {
        return nullptr;
    }

    // TODO
    return nullptr;
}

////////////////////////////////////////////////////////////
// Attributes
// Update function attributes
void
UnknownFrontendTranslatorImplX86::UpdateFunctionAttributes(uir::Function *F)
{
    assert(F);

    // Get function attributes from the config file
    auto Attributes = mConfigReader->getFunctionAttributes(F->getFunctionName());

    // Add function attributes to the function
    for (const auto &Attr : Attributes)
    {
        if (!Attr.empty())
        {
            F->addFnAttr(Attr);
        }
    }
}

void
UnknownFrontendTranslatorImplX86::UpdateFunctionAttributes(
    const unknown::SymbolParser::FunctionSymbol &FunctionSymbol,
    uir::Function *F)
{
    assert(F);

    auto FunctionAddress = FunctionSymbol.rva + mBinary->imagebase();
    auto FunctionSize = FunctionSymbol.size;

    F->setFunctionName(FunctionSymbol.name);
    F->setFunctionBeginAddress(FunctionAddress);
    F->setFunctionEndAddress(FunctionAddress + FunctionSize);

    if (hasUsePDB())
    {
        F->setSEH(FunctionSymbol.hasSEH);
        F->setAsyncEH(FunctionSymbol.hasAsyncEH);
        F->setNaked(FunctionSymbol.hasNaked);
    }

    UpdateFunctionAttributes(F);
}

// Update function context
void
UnknownFrontendTranslatorImplX86::UpdateFunctionContext(uir::Function *F)
{
    assert(F);

    // TODO
}

// Update BasicBlock attributes
void
UnknownFrontendTranslatorImplX86::UpdateBasicBlockAttributes(uir::BasicBlock *BB)
{
    assert(BB);

    // TODO
}

} // namespace ufrontend

#include "TranslatorImpl.x86.h"

#include <unknown/ADT/ScopeExit.h>

namespace ufrontend {

UnknownFrontendTranslatorImplX86::UnknownFrontendTranslatorImplX86(
    uir::Context &C,
    const Platform Platform,
    const std::string &BinaryFile,
    const std::string &SymbolFile) :
    UnknownFrontendTranslatorImpl(C, Platform, BinaryFile, SymbolFile), mUsePDB(false)
{
    mTarget = unknown::CreateTargetForX86(C.getModeBits());

    openCapstoneHandle();
    initSymbolParser();
    initBinary();
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
        std::cerr << cs_strerror(cs_errno(CapstoneHandle)) << std::endl;
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
            std::cerr << cs_strerror(cs_errno(CapstoneHandle)) << std::endl;
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
            std::cerr << "UnknownFrontend: Error: Symbol file is not a .map/.pdb file" << std::endl;
            std::abort();
        }
    }

    mSymbolParser = unknown::CreateSymbolParserForPE(UsePDB);
    assert(mSymbolParser);

    if (!mSymbolParser->ParseFunctionSymbols(getSymbolFile()))
    {
        std::cerr << "UnknownFrontend: Error: ParseFunctionSymbols failed" << std::endl;
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
// Translate the given binary into UnknownIR
std::unique_ptr<uir::Module>
UnknownFrontendTranslatorImplX86::translateBinary(const std::string &ModuleName)
{
    auto Module = uir::Module::get(getContext(), ModuleName);
    assert(Module);

    for (auto &FunctionSymbol : mSymbolParser->getFunctionSymbols())
    {
        auto F = new uir::Function(getContext());
        assert(F);

        // Translate one function into UnknownIR
        bool TransRes = translateOneFunction(FunctionSymbol, F);
        if (TransRes)
        {
            // Insert a function into the module
            Module->insertFunction(F);
        }
        else
        {
            std::cerr << std::format("UnknownFrontend: Error: translateOneFunction: {} failed", F->getFunctionName())
                      << std::endl;
            delete F;
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
        std::cerr << std::format("UnknownFrontend: Error: disasm: 0x{:X} failed", Address) << std::endl;
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
    do
    {
        // Ret
        if (TransRes = translateRetInstruction(Insn, Address, BB))
        {
            IsBlockTerminatorInsn = true;
            break;
        }

        // Jcc
        if (TransRes = translateJccInstruction(Insn, Address, BB))
        {
            IsBlockTerminatorInsn = true;
            break;
        }

    } while (false);

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

    auto TempBB = std::make_unique<uir::BasicBlock>(getContext(), BlockName, Address, MaxAddress);
    assert(TempBB);

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
            std::cerr << std::format("UnknownFrontend: Error: disasm: 0x{:X} failed", Address) << std::endl;
            break;
        }

        // Translate one instruction
        bool IsTerminatorInsn = false;
        bool TransRes = translateOneInstruction(Insn, Address, TempBB.get(), IsTerminatorInsn);
        if (!TransRes)
        {
            std::cerr << std::format("UnknownFrontend: Error: translateOneInstruction: 0x{:X} failed", Address)
                      << std::endl;
            break;
        }

        if (IsTerminatorInsn)
        {
            break;
        }

        // Update ptr
        setCurPtrBegin(Address + Insn->size);
    }

    return TempBB.release();
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

    // Set the current function
    setCurFunction(F);

    // Set the begin of current pointer
    setCurPtrBegin(Address ? Address : F->getFunctionBeginAddress());
    assert(getCurPtrBegin());

    // Set the end of current pointer
    setCurPtrEnd(Size ? Address + Size : F->getFunctionEndAddress());
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

    auto TempFunction = std::make_unique<uir::Function>(getContext());
    assert(TempFunction);

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
            TempFunction->insertBasicBlock(BB);
        }

        // Update ptr
        setCurPtrBegin(BB->getBasicBlockAddressEnd());
    }

    if (TempFunction->empty())
    {
        return false;
    }

    // Fill the function
    for (auto It = TempFunction->begin(); It != TempFunction->end(); ++It)
    {
        auto BB = *It;
        assert(BB);

        // Insert a BasicBlock into the function
        F->insertBasicBlock(BB);
    }

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
UnknownFrontendTranslatorImplX86::getRegisterName(uint32_t RegID)
{
    return mTarget->getRegisterName(RegID);
}

// Get the register id by register name
uint32_t
UnknownFrontendTranslatorImplX86::getRegisterID(const std::string &RegName)
{
    return mTarget->getRegisterID(RegName);
}

// Get carry register
uint32_t
UnknownFrontendTranslatorImplX86::getCarryRegister()
{
    return mTarget->getCarryRegister();
}

////////////////////////////////////////////////////////////
// Attributes
// Update function attributes
void
UnknownFrontendTranslatorImplX86::UpdateFunctionAttributes(uir::Function *F)
{
    assert(F);

    UpdateFunctionAttributesForSEH(F);
    UpdateFunctionAttributesForCXXEH(F);
}

void
UnknownFrontendTranslatorImplX86::UpdateFunctionAttributes(
    const unknown::SymbolParser::FunctionSymbol &FunctionSymbol,
    uir::Function *F)
{
    assert(F);

    auto FunctionAddress = FunctionSymbol.rva + mBinary->imagebase();
    auto FunctionSize = FunctionSymbol.size;
    auto &FunctionName = FunctionSymbol.name;

    F->setFunctionName(FunctionName);
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

void
UnknownFrontendTranslatorImplX86::UpdateFunctionAttributesForSEH(uir::Function *F)
{
    assert(F);

    // TODO
}

void
UnknownFrontendTranslatorImplX86::UpdateFunctionAttributesForCXXEH(uir::Function *F)
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

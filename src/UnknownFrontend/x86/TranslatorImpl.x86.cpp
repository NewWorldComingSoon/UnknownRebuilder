#include "TranslatorImpl.x86.h"

namespace ufrontend {

UnknownFrontendTranslatorImplX86::UnknownFrontendTranslatorImplX86(
    uir::Context &C,
    const std::string &BinaryFile,
    const std::string &SymbolFile) :
    UnknownFrontendTranslatorImpl(C, BinaryFile, SymbolFile)
{
    //
}

UnknownFrontendTranslatorImplX86::~UnknownFrontendTranslatorImplX86()
{
    //
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
    switch (getContext().getModeBits())
    {
    case 32:
        return X86_REG_ESP;
    case 64:
        return X86_REG_RSP;
    default: {
        std::cerr << "UnknownFrontend: Error: getStackPointerRegister failed" << std::endl;
        std::abort();
        break;
    }
    }
}

const unknown::StringRef
UnknownFrontendTranslatorImplX86::getStackPointerRegisterName() const
{
    switch (getContext().getModeBits())
    {
    case 32:
        return "ESP";
    case 64:
        return "RSP";
    default: {
        std::cerr << "UnknownFrontend: Error: getStackPointerRegisterName failed" << std::endl;
        std::abort();
        break;
    }
    }
}

const uint32_t
UnknownFrontendTranslatorImplX86::getBasePointerRegister() const
{
    switch (getContext().getModeBits())
    {
    case 32:
        return X86_REG_EBP;
    case 64:
        return X86_REG_RBP;
    default: {
        std::cerr << "UnknownFrontend: Error: getBasePointerRegister failed" << std::endl;
        std::abort();
        break;
    }
    }
}

const unknown::StringRef
UnknownFrontendTranslatorImplX86::getBasePointerRegisterName() const
{
    switch (getContext().getModeBits())
    {
    case 32:
        return "EBP";
    case 64:
        return "RBP";
    default: {
        std::cerr << "UnknownFrontend: Error: getBasePointerRegisterName failed" << std::endl;
        std::abort();
        break;
    }
    }
}

////////////////////////////////////////////////////////////
// Translate
// Translate the given binary into UnknownIR
std::unique_ptr<uir::Module>
UnknownFrontendTranslatorImplX86::translateBinary(const std::string &ModuleName)
{
    // TODO
    return {};
}

// Translate one instruction into UnknownIR
bool
UnknownFrontendTranslatorImplX86::translateOneInstruction(
    const uint8_t *Bytes,
    size_t Size,
    uint64_t Address,
    uir::BasicBlock *BB)
{
    // TODO
    return true;
}

bool
UnknownFrontendTranslatorImplX86::translateOneInstruction(const cs_insn *Insn, uint64_t Address, uir::BasicBlock *BB)
{
    // TODO
    return true;
}

// Translate one BasicBlock into UnknownIR
uir::BasicBlock *
UnknownFrontendTranslatorImplX86::translateOneBasicBlock(const std::string &BlockName, uint64_t Address)
{
    // TODO
    return nullptr;
}

// Translate one Function into UnknownIR
uir::Function *
UnknownFrontendTranslatorImplX86::translateOneFunction(const std::string &FunctionName, uint64_t Address)
{
    // TODO
    return nullptr;
}

} // namespace ufrontend

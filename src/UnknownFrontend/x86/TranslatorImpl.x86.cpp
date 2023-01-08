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
    assert(!mSymbolFile.empty());

    bool UsePDB = false;
    if (mSymbolFile.rfind(".pdb") != std::string::npos)
    {
        UsePDB = true;
    }

    if (!UsePDB)
    {
        if (mSymbolFile.rfind(".map") == std::string::npos)
        {
            std::cerr << "UnknownFrontend: Error: Symbol file is not a .map/.pdb file" << std::endl;
            std::abort();
        }
    }

    mSymbolParser = unknown::CreateSymbolParserForPE(UsePDB);
    assert(mSymbolParser);

    if (!mSymbolParser->ParseFunctionSymbols(mSymbolFile))
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
    assert(!mBinaryFile.empty());

    mBinary = LIEF::PE::Parser::parse(mBinaryFile);
    assert(mBinary);
}

////////////////////////////////////////////////////////////
// Translate
// Translate the given binary into UnknownIR
std::unique_ptr<uir::Module>
UnknownFrontendTranslatorImplX86::translateBinary()
{
    // TODO
    return {};
}

} // namespace ufrontend

#include <UnknownFrontend/UnknownFrontend.h>

#include <x86/TranslatorImpl.x86.h>
#include <arm/TranslatorImpl.arm.h>

namespace ufrontend {

////////////////////////////////////////////////////////////
// Static
std::unique_ptr<UnknownFrontendTranslator>
UnknownFrontendTranslator::createArch(uir::Context &C, const std::string &BinaryFile, const std::string &SymbolFile)
{
    if (C.getArch() == uir::Context::Arch::ArchX86)
    {
        return std::make_unique<UnknownFrontendTranslatorImplX86>(C, BinaryFile, SymbolFile);
    }
    else if (C.getArch() == uir::Context::Arch::ArchARM)
    {
        return std::make_unique<UnknownFrontendTranslatorImplARM>(C, BinaryFile, SymbolFile);
    }

    return {};
}

} // namespace ufrontend

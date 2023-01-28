#include <UnknownFrontend/UnknownFrontend.h>

#include <x86/TranslatorImpl.x86.h>
#include <arm/TranslatorImpl.arm.h>

namespace ufrontend {

////////////////////////////////////////////////////////////
// Static
std::unique_ptr<UnknownFrontendTranslator>
UnknownFrontendTranslator::createTranslator(
    uir::Context &C,
    const std::string &BinaryFile,
    const std::string &SymbolFile,
    const std::string &ConfigFile,
    bool AnalyzeAllFunctions,
    const Platform Platform)
{
    switch (C.getArch())
    {
    case uir::Context::Arch::ArchX86:
        return std::make_unique<UnknownFrontendTranslatorImplX86>(
            C, Platform, BinaryFile, SymbolFile, ConfigFile, AnalyzeAllFunctions);
    case uir::Context::Arch::ArchARM:
        return std::make_unique<UnknownFrontendTranslatorImplARM>(
            C, Platform, BinaryFile, SymbolFile, ConfigFile, AnalyzeAllFunctions);
    default:
        // TODO
        break;
    }

    return {};
}

} // namespace ufrontend

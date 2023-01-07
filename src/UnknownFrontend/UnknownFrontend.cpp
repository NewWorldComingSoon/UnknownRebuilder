#include <UnknownFrontend/UnknownFrontend.h>

#include <x86/TranslatorImpl.x86.h>

namespace ufrontend {

////////////////////////////////////////////////////////////
// Static
std::unique_ptr<UnknownFrontendTranslator>
UnknownFrontendTranslator::createArch(uir::Context &C)
{
    if (C.getArch() == uir::Context::Arch::ArchX86)
    {
        return std::make_unique<UnknownFrontendTranslatorImplX86>(C);
    }
    else
    {
        // TODO
    }

    return {};
}

} // namespace ufrontend

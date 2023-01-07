#include "TranslatorImpl.arm.h"

namespace ufrontend {

UnknownFrontendTranslatorImplARM::UnknownFrontendTranslatorImplARM(
    uir::Context &C,
    const std::string &BinaryFile,
    const std::string &SymbolFile) :
    UnknownFrontendTranslatorImpl(C, BinaryFile, SymbolFile)
{
    openCapstoneHandle();
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
// Translate
std::unique_ptr<uir::Module>
UnknownFrontendTranslatorImplARM::translateBinary()
{
    // TODO
    return {};
}

} // namespace ufrontend

#pragma once
#include <UnknownFrontend/UnknownFrontend.h>

namespace ufrontend {

class UnknownFrontendTranslatorImpl : public UnknownFrontendTranslator
{
public:
    UnknownFrontendTranslatorImpl(uir::Context &C);
    virtual ~UnknownFrontendTranslatorImpl();
};

} // namespace ufrontend

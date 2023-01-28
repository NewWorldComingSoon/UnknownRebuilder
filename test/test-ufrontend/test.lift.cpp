
#include <UnknownFrontend/UnknownFrontend.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

TEST(test_lift, test_lift_1)
{
    std::cout << "---------------lift----------------\n";

    uir::Context CTX;
    CTX.setArch(uir::Context::Arch::ArchX86);
    CTX.setMode(uir::Context::Mode::Mode64);

    auto Translator = ufrontend::UnknownFrontendTranslator::createTranslator(
        CTX,
        UNKNOWN_REBUILDER_SRC_DIR R"(/sample/pe-x64/Project12.exe)",
        UNKNOWN_REBUILDER_SRC_DIR R"(/sample/pe-x64/Project12.pdb)",
        UNKNOWN_REBUILDER_SRC_DIR R"(/sample/pe-x64/Project12.cfg.xml)",
        false);
    assert(Translator);
    Translator->initTranslator();

    auto Module = Translator->translateBinary("Project12");
    assert(Module);
    Module->print(unknown::outs());
}

TEST(test_lift, test_lift_2)
{
    std::cout << "---------------lift----------------\n";

    uir::Context CTX;
    CTX.setArch(uir::Context::Arch::ArchX86);
    CTX.setMode(uir::Context::Mode::Mode64);

    auto Translator = ufrontend::UnknownFrontendTranslator::createTranslator(
        CTX,
        UNKNOWN_REBUILDER_SRC_DIR R"(/sample/pe-x64/Project12.exe)",
        UNKNOWN_REBUILDER_SRC_DIR R"(/sample/pe-x64/Project12.pdb)",
        UNKNOWN_REBUILDER_SRC_DIR R"(/sample/pe-x64/Project12.cfg2.xml)",
        false);
    assert(Translator);
    Translator->initTranslator();

    auto Module = Translator->translateBinary("Project12-2");
    assert(Module);
    Module->print(unknown::outs());
}

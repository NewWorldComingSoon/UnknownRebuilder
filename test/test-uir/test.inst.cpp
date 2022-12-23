#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

using namespace uir;

TEST(test_uir, test_uir_inst_1)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    std::cout << "RetIMMOpCodeName = " << std::format("{}", RetIMMComponent.mOpCodeName.data()) << std::endl;

    auto ReturnImmIst = ReturnImmInst::get(ConstantInt::get(CTX, 1, 32));
    auto ImmCstInt = ReturnImmIst->getImmConstantInt();
    if (ImmCstInt)
    {
        std::cout << "ImmCstInt->getZExtValue() = " << std::format("{}", ImmCstInt->getZExtValue()) << std::endl;

        // Update op1
        ReturnImmIst->setImmConstantInt(ConstantInt::get(CTX, 2, 32));
        auto ImmCstInt2 = ReturnImmIst->getImmConstantInt();
        std::cout << "ImmCstInt2->getZExtValue() = " << std::format("{}", ImmCstInt->getZExtValue()) << std::endl;
    }
}

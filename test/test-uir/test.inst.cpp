#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <stdio.h>
#include <stdlib.h>

using namespace uir;

TEST(test_uir, test_uir_inst_1)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    printf("RetIMMOpCodeName = %s\n", RetIMMComponent.mOpCodeName.data());

    auto ReturnImmIst = ReturnImmInst::get(ConstantInt::get(CTX, 1, 32));
    auto ImmCstInt = ReturnImmIst->getImmConstantInt();
    if (ImmCstInt)
    {
        printf("ImmCstInt->getZExtValue() = %lld\n", ImmCstInt->getZExtValue());

        // Update op1
        ReturnImmIst->setImmConstantInt(ConstantInt::get(CTX, 2, 32));
        auto ImmCstInt2 = ReturnImmIst->getImmConstantInt();
        printf("ImmCstInt2->getZExtValue() = %lld\n", ImmCstInt2->getZExtValue());
    }
}

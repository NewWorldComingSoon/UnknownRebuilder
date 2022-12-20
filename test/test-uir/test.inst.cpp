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

    printf("AddOpCodeName = %s\n", AddComponent.mOpCodeName.c_str());
}

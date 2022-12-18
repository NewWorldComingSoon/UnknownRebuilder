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

    for (auto &Item : GlobalOpCodeComponents)
    {
        printf("OpCodeName = %s\n", Item.mOpCodeName.c_str());
    }
}

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

    size_t Size = sizeof(GlobalOpCodeComponents) / sizeof(GlobalOpCodeComponents[0]) - 1;
    for (size_t i = 0; i < Size; ++i)
    {
        printf("OpCodeName = %s\n", GlobalOpCodeComponents[i].mOpCodeName.c_str());
    }
}

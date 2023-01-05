#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

using namespace uir;

TEST(test_uir, test_uir_bb_1)
{
    {
        Context CTX;
        CTX.setArch(Context::Arch::ArchX86);
        CTX.setMode(Context::Mode::Mode64);

        BasicBlock BB1(CTX, "bb1", 0x401000, 0x401005);

        IRBuilder IBR(&BB1);
        auto ret1 = IBR.createRetVoid(0x401000);
        auto retimm1 = IBR.createRetImm(ConstantInt::get(CTX, unknown::APInt(32, 1)), 0x401005);
        IBR.setInsertPoint(ret1);
        auto ret2 = IBR.createRetVoid(0x401007);

        for (auto I : BB1)
        {
            unknown::outs() << *I;
        }

        unknown::outs() << BB1;
    }

    std::cout << "--------------------bp-----------------------" << std::endl;
}
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
        auto RetInst = ReturnInstruction::get();
        RetInst->setInstructionAddress(0x401000);
        BB1.insertInst(RetInst);

        auto RetImm = ReturnImmInstruction::get(ConstantInt::get(CTX, unknown::APInt(32, 1)));
        RetImm->setInstructionAddress(0x401005);
        BB1.insertInst(RetImm);

        for (auto I : BB1)
        {
            unknown::outs() << *I;
        }

        unknown::outs() << BB1;
    }

    std::cout << "--------------------bp-----------------------" << std::endl;
}
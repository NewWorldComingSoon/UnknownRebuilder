#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

using namespace uir;

TEST(test_uir, test_uir_bb_1)
{
    {
        Context CTX;
        CTX.setArch(Context::ArchX86);
        CTX.setMode(Context::Mode64);

        auto BB1 = BasicBlock::create(CTX, "bb1", 0x401000, 0x401005);
        auto RetInst = ReturnInstruction::get();
        RetInst->setInstructionAddress(0x401000);
        BB1->insertInst(RetInst);
        BB1->insertInst(RetInst);
        for (auto I : *BB1)
        {
            unknown::outs() << *I;
        }
    }

    std::cout << "--------------------bp-----------------------\n";
}
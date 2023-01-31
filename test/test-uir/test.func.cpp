#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

using namespace uir;

TEST(test_uir, test_uir_func_1)
{
    {
        Context CTX;
        CTX.setArch(Context::Arch::ArchX86);
        CTX.setMode(Context::Mode::Mode64);

        Function F(CTX, "func1");

        F.setFunctionBeginAddress(0x401000);
        F.setFunctionEndAddress(0x401010);

        F.addFnAttr("new");

        F.insertArgument(Argument::get(Type::getInt32Ty(CTX), "arg1", &F, 0));
        F.insertArgument(Argument::get(Type::getInt32Ty(CTX), "arg2", &F, 1));

        F.insertFunctionContext(FunctionContext::get(Type::getInt32Ty(CTX), "eax", &F, 0));
        F.insertFunctionContext(FunctionContext::get(Type::getInt32Ty(CTX), "ebx", &F, 2));

        BasicBlock *BB1 = BasicBlock::get(CTX, "bb1", 0x401000, 0x401005);
        BasicBlock *BB2 = BasicBlock::get(CTX, "bb2", 0x401007, 0x401010);

        auto RetInst = ReturnInstruction::get(CTX);
        RetInst->setInstructionAddress(0x401000);
        BB1->insertInst(RetInst);

        auto JmpBBInst = JmpBBInstruction::get(CTX, BB2);
        JmpBBInst->setInstructionAddress(0x401005);
        JmpBBInst->insertAfter(RetInst);

        auto RetInst2 = ReturnInstruction::get(CTX);
        RetInst2->setInstructionAddress(0x401007);
        BB2->insertInst(RetInst2);

        IRBuilder IRB(BB2);
        auto RetImm21 = IRB.createRetImm(ConstantInt::get(Type::getInt16Ty(CTX), unknown::APInt(32, 4)), 0x401008);

        IRBuilder IRB2(BB2);
        IRB2.createRetImm(ConstantInt::get(Type::getInt16Ty(CTX), unknown::APInt(32, 6)), 0x401008);

        IRB2.setInsertPoint(RetImm21);
        IRB2.createRetImm(ConstantInt::get(Type::getInt16Ty(CTX), unknown::APInt(32, 5)), 0x401010);

        F.insertBasicBlock(BB1);
        F.insertBasicBlock(BB2);

        // F.print(unknown::outs());

        unknown::outs() << F;
    }

    std::cout << "--------------------bp-----------------------" << std::endl;
}
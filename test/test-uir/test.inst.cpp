#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

using namespace uir;

TEST(test_uir, test_uir_inst_RetIMM_1)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    std::cout << std::format("RetIMMOpCodeName = {}", RetIMMComponent.mOpCodeName.data()) << std::endl;

    auto ReturnImmInst = ReturnImmInstruction::get(ConstantInt::get(CTX, 1, 32));
    ReturnImmInst->setInstructionAddress(0x401000);
    ReturnImmInst->print(unknown::outs());
    unknown::outs() << *ReturnImmInst;

    auto ImmCstInt = ReturnImmInst->getImmConstantInt();
    if (ImmCstInt)
    {
        std::cout << std::format("ImmCstInt->getZExtValue() = {}", ImmCstInt->getZExtValue()) << std::endl;

        // Update op1
        ReturnImmInst->setImmConstantInt(ConstantInt::get(CTX, 2, 32));
        auto ImmCstInt2 = ReturnImmInst->getImmConstantInt();
        std::cout << std::format("ImmCstInt2->getZExtValue() = {}", ImmCstInt->getZExtValue()) << std::endl;
        ReturnImmInst->setInstructionAddress(0x401001);
        ReturnImmInst->print(unknown::outs());
        unknown::outs() << *ReturnImmInst;
    }

    for (auto OpIt = ReturnImmInst->op_begin(); OpIt != ReturnImmInst->op_end(); ++OpIt)
    {
        auto Op = *OpIt;
        std::cout << std::format("Op = {}", Op->getName()) << std::endl;
    }
}

TEST(test_uir, test_uir_inst_Store_1)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    std::cout << std::format("StoreComponent = {}", StoreComponent.mOpCodeName.data()) << std::endl;

    auto Val = LocalVariable::get(Type::getInt32Ty(CTX), "local_1", 0x501000);
    auto Ptr = LocalVariable::get(Type::getInt32PtrTy(CTX), "local_ptr_1", 0x601000);

    auto StoreInst = StoreInstruction::get(Val, Ptr);
    StoreInst->setInstructionAddress(0x401000);
    StoreInst->print(unknown::outs());
    unknown::outs() << *StoreInst;

    for (auto OpIt = StoreInst->op_begin(); OpIt != StoreInst->op_end(); ++OpIt)
    {
        auto Op = *OpIt;
        std::cout << std::format("Op = {}", Op->getName()) << std::endl;
    }
}

TEST(test_uir, test_uir_inst_Ret_1)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    std::cout << std::format("RetComponent = {}", RetComponent.mOpCodeName.data()) << std::endl;

    auto RetInst = ReturnInstruction::get();
    RetInst->setInstructionAddress(0x401000);
    RetInst->print(unknown::outs());
    unknown::outs() << *RetInst;
}

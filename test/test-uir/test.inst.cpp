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

    auto ReturnImmIst = ReturnImmInst::get(ConstantInt::get(CTX, 1, 32));
    ReturnImmIst->setInstructionAddress(0x401000);
    ReturnImmIst->print(unknown::outs());

    auto ImmCstInt = ReturnImmIst->getImmConstantInt();
    if (ImmCstInt)
    {
        std::cout << std::format("ImmCstInt->getZExtValue() = {}", ImmCstInt->getZExtValue()) << std::endl;

        // Update op1
        ReturnImmIst->setImmConstantInt(ConstantInt::get(CTX, 2, 32));
        auto ImmCstInt2 = ReturnImmIst->getImmConstantInt();
        std::cout << std::format("ImmCstInt2->getZExtValue() = {}", ImmCstInt->getZExtValue()) << std::endl;
        ReturnImmIst->setInstructionAddress(0x401001);
        ReturnImmIst->print(unknown::outs());
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

    auto StoreIst = StoreInst::get(Val, Ptr);
    StoreIst->setInstructionAddress(0x401000);
    StoreIst->print(unknown::outs());
}

TEST(test_uir, test_uir_inst_Ret_1)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    std::cout << std::format("RetComponent = {}", RetComponent.mOpCodeName.data()) << std::endl;

    auto RetIst = ReturnInst::get();
    RetIst->setInstructionAddress(0x401000);
    RetIst->print(unknown::outs());
}

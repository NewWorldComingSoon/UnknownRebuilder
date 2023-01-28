#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

using namespace uir;

TEST(test_uir, test_uir_inst_RetIMM_1)
{
    Context CTX;
    CTX.setArch(Context::Arch::ArchX86);
    CTX.setMode(Context::Mode::Mode64);

    std::cout << std::format("RetIMMOpCodeName = {}", RetIMMComponent.mOpCodeName.data()) << std::endl;

    auto ReturnImmInst = ReturnImmInstruction::get(CTX, ConstantInt::get(CTX, unknown::APInt(32, 1)));
    ReturnImmInst->setInstructionAddress(0x401000);

    ReturnImmInst->enablePrintOp();

    ReturnImmInst->print(unknown::outs());
    unknown::outs() << *ReturnImmInst;

    auto ImmCstInt = ReturnImmInst->getImmConstantInt();
    if (ImmCstInt)
    {
        std::cout << std::format("ImmCstInt->getZExtValue() = {}", ImmCstInt->getZExtValue()) << std::endl;

        // Update op1
        ReturnImmInst->setImmConstantInt(ConstantInt::get(CTX, unknown::APInt(32, 1)));
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
    CTX.setArch(Context::Arch::ArchX86);
    CTX.setMode(Context::Mode::Mode64);

    std::cout << std::format("StoreComponent = {}", StoreComponent.mOpCodeName.data()) << std::endl;

    auto Val = LocalVariable::get(Type::getInt32Ty(CTX), "local_1", 0x501000);
    auto Ptr = LocalVariable::get(Type::getInt32PtrTy(CTX), "local_ptr_1", 0x601000);

    auto StoreInst = StoreInstruction::get(CTX, Val, Ptr);
    StoreInst->setInstructionAddress(0x401000);

    StoreInst->enablePrintOp();

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
    CTX.setArch(Context::Arch::ArchX86);
    CTX.setMode(Context::Mode::Mode64);

    std::cout << std::format("RetComponent = {}", RetComponent.mOpCodeName.data()) << std::endl;

    auto RetInst = ReturnInstruction::get(CTX);
    RetInst->setInstructionAddress(0x401000);

    RetInst->enablePrintOp();

    RetInst->print(unknown::outs());

    unknown::outs() << *RetInst;
}

TEST(test_uir, test_uir_inst_JmpAddr_1)
{
    Context CTX;
    CTX.setArch(Context::Arch::ArchX86);
    CTX.setMode(Context::Mode::Mode64);

    std::cout << std::format("JmpAddrComponent = {}", JmpAddrComponent.mOpCodeName.data()) << std::endl;

    auto JmpAddrInst = JmpAddrInstruction::get(CTX, ConstantInt::get(CTX, unknown::APInt(64, 0x406000)));
    JmpAddrInst->setInstructionAddress(0x401000);

    JmpAddrInst->enablePrintOp();

    JmpAddrInst->print(unknown::outs());

    unknown::outs() << *JmpAddrInst;
}

TEST(test_uir, test_uir_inst_JmpBB_1)
{
    Context CTX;
    CTX.setArch(Context::Arch::ArchX86);
    CTX.setMode(Context::Mode::Mode64);

    std::cout << std::format("JmpBBComponent = {}", JmpBBComponent.mOpCodeName.data()) << std::endl;

    auto BB = BasicBlock::get(CTX, "bb1", 0x406000, 0x406005);
    auto JmpBBInst = JmpBBInstruction::get(CTX, BB);
    JmpBBInst->setInstructionAddress(0x401000);
    JmpBBInst->enablePrintOp();
    JmpBBInst->print(unknown::outs());
    unknown::outs() << *JmpBBInst;
}

TEST(test_uir, test_uir_inst_JccAddr_1)
{
    Context CTX;
    CTX.setArch(Context::Arch::ArchX86);
    CTX.setMode(Context::Mode::Mode64);

    std::cout << std::format("JccAddrComponent = {}", JccAddrComponent.mOpCodeName.data()) << std::endl;

    auto Addr1 = ConstantInt::get(CTX, unknown::APInt(64, 0x406000));
    auto Addr2 = ConstantInt::get(CTX, unknown::APInt(64, 0x407000));

    auto FlagsVar = FlagsVariable::get(CTX);
    FlagsVar->setCarryFlag(true);
    FlagsVar->setZeroFlag(true);

    auto JccAddrInst = JccAddrInstruction::get(CTX, Addr1, Addr2, FlagsVar);
    JccAddrInst->setInstructionAddress(0x401000);
    JccAddrInst->enablePrintOp();
    JccAddrInst->print(unknown::outs());
    unknown::outs() << *JccAddrInst;
}

TEST(test_uir, test_uir_inst_JccBB_1)
{
    Context CTX;
    CTX.setArch(Context::Arch::ArchX86);
    CTX.setMode(Context::Mode::Mode64);

    std::cout << std::format("JccBBComponent = {}", JccBBComponent.mOpCodeName.data()) << std::endl;

    auto BB1 = BasicBlock::get(CTX, "bb1", 0x406000, 0x406005);
    auto BB2 = BasicBlock::get(CTX, "bb2", 0x407600, 0x407605);

    auto FlagsVar = FlagsVariable::get(CTX);
    FlagsVar->setCarryFlag(true);
    FlagsVar->setZeroFlag(true);

    auto JccBBInst = JccBBInstruction::get(CTX, BB1, BB2, FlagsVar);
    JccBBInst->setInstructionAddress(0x401000);
    JccBBInst->enablePrintOp();
    JccBBInst->print(unknown::outs());
    unknown::outs() << *JccBBInst;
}

TEST(test_uir, test_uir_inst_GBP_1)
{
    Context CTX;
    CTX.setArch(Context::Arch::ArchX86);
    CTX.setMode(Context::Mode::Mode64);

    std::cout << std::format("GBPComponent = {}", GBPComponent.mOpCodeName.data()) << std::endl;

    auto Ptr = LocalVariable::get(Type::getInt32PtrTy(CTX), "ptr1", 0x601000);
    auto BitIndex = ConstantInt::get(Type::getInt32Ty(CTX), unknown::APInt(32, 8));

    auto GBPInst = GetBitPtrInstruction::get(Type::getInt8PtrTy(CTX), Ptr, BitIndex);
    GBPInst->setInstructionAddress(0x401000);

    GBPInst->enablePrintOp();

    GBPInst->print(unknown::outs());
    unknown::outs() << *GBPInst;

    for (auto OpIt = GBPInst->op_begin(); OpIt != GBPInst->op_end(); ++OpIt)
    {
        auto Op = *OpIt;
        std::cout << std::format("Op = {}", Op->getName()) << std::endl;
    }
}

TEST(test_uir, test_uir_inst_Load_1)
{
    Context CTX;
    CTX.setArch(Context::Arch::ArchX86);
    CTX.setMode(Context::Mode::Mode64);

    std::cout << std::format("LoadComponent = {}", LoadComponent.mOpCodeName.data()) << std::endl;

    auto Ptr = LocalVariable::get(Type::getInt32PtrTy(CTX), "ptr1", 0x601000);

    auto LoadInst = LoadInstruction::get(Ptr);
    LoadInst->setInstructionAddress(0x401000);

    LoadInst->enablePrintOp();

    LoadInst->print(unknown::outs());
    unknown::outs() << *LoadInst;

    for (auto OpIt = LoadInst->op_begin(); OpIt != LoadInst->op_end(); ++OpIt)
    {
        auto Op = *OpIt;
        std::cout << std::format("Op = {}", Op->getName()) << std::endl;
    }
}

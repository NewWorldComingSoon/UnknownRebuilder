#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

using namespace uir;

TEST(test_uir, test_uir_value_1)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    ConstantInt *Val2 = new ConstantInt(Type::getInt32Ty(CTX), unknown::APInt(32, 0x7b));
    std::cout << std::hex
              << std::format("Val1 ReadableName = {}, ZExtValue = {}", Val2->getReadableName(), Val2->getZExtValue())
              << std::endl;
    unknown::outs() << "Val2 ReadableName = " << *Val2;

    Value *Val3 = new GlobalVariable(Type::getInt32Ty(CTX), "global_1", 0x401000);
    std::cout << std::format("Val3 ReadableName = {}", Val3->getReadableName()) << std::endl;
    unknown::outs() << "Val3 ReadableName = " << *Val3;

    Value *Val4 = new LocalVariable(Type::getInt32Ty(CTX), "local_1", 0x401000);
    std::cout << std::format("Val4 ReadableName = {}", Val4->getReadableName()) << std::endl;
    unknown::outs() << "Val4 ReadableName = " << *Val4;
}

TEST(test_uir, test_uir_value_2)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    Value *Ptr2 = new ConstantInt(Type::getInt32PtrTy(CTX), unknown::APInt(32, 123));
    std::cout << std::format("Ptr2 ReadableName = {}", Ptr2->getReadableName()) << std::endl;
    unknown::outs() << "Ptr2 ReadableName = " << *Ptr2;

    Value *Ptr3 = new GlobalVariable(Type::getInt32PtrTy(CTX), "global_ptr_1", 0x401000);
    std::cout << std::format("Ptr3 ReadableName = {}", Ptr3->getReadableName()) << std::endl;
    unknown::outs() << "Ptr3 ReadableName = " << *Ptr3;

    Value *Ptr4 = new LocalVariable(Type::getInt32PtrTy(CTX), "local_ptr_1", 0x401000);
    std::cout << std::format("Ptr4 ReadableName = {}", Ptr4->getReadableName()) << std::endl;
    unknown::outs() << "Ptr4 ReadableName = " << *Ptr4;
}

TEST(test_uir, test_uir_value_3)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    Value *Val11 =
        new GlobalVariable(Type::getInt32Ty(CTX), GlobalVariable::generateOrderedGlobalVarName(CTX).c_str(), 0x401000);
    std::cout << std::format("Val11 ReadableName = {}", Val11->getReadableName()) << std::endl;
    unknown::outs() << "Val11 ReadableName = " << *Val11;

    Value *Val12 =
        new GlobalVariable(Type::getInt32Ty(CTX), GlobalVariable::generateOrderedGlobalVarName(CTX).c_str(), 0x401000);
    std::cout << std::format("Val12 ReadableName = {}", Val12->getReadableName()) << std::endl;
    unknown::outs() << "Val12 ReadableName = " << *Val12;

    Value *Val21 =
        new LocalVariable(Type::getInt32Ty(CTX), LocalVariable::generateOrderedLocalVarName(CTX).c_str(), 0x401000);
    std::cout << std::format("Val21 ReadableName = {}", Val21->getReadableName()) << std::endl;
    unknown::outs() << "Val21 ReadableName = " << *Val21;

    Value *Val22 =
        new LocalVariable(Type::getInt32Ty(CTX), LocalVariable::generateOrderedLocalVarName(CTX).c_str(), 0x401000);
    std::cout << std::format("Val22 ReadableName = {}", Val22->getReadableName()) << std::endl;
    unknown::outs() << "Val22 ReadableName = " << *Val22;
}

TEST(test_uir, test_uir_value_4)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    auto CSTInt = ConstantInt::get(CTX, unknown::APInt(32, 0x25474));
    std::cout << std::format("CSTInt getZExtValue =  {}", CSTInt->getZExtValue()) << std::endl;
    std::cout << std::format("CSTInt ReadableName =  {}", CSTInt->getReadableName()) << std::endl;
    unknown::outs() << "CSTInt ReadableName = " << *CSTInt;
}

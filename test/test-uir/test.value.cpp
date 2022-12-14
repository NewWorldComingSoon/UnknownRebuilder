#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <stdio.h>
#include <stdlib.h>

using namespace uir;

TEST(test_uir, test_uir_value_1)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    Value *Val1 = new Constant(Type::getInt32Ty(CTX), "const_1");
    printf("Val1 ReadableName = %s\n", Val1->getReadableName().c_str());

    ConstantInt *Val2 = new ConstantInt(Type::getInt32Ty(CTX), 0x7b);
    printf("Val2 ReadableName = %s, ZExtValue = %llx\n", Val2->getReadableName().c_str(), Val2->getZExtValue());

    Value *Val3 = new GlobalVariable(Type::getInt32Ty(CTX), "global_1");
    printf("Val3 ReadableName = %s\n", Val3->getReadableName().c_str());

    Value *Val4 = new LocalVariable(Type::getInt32Ty(CTX), "local_1");
    printf("Val4 ReadableName = %s\n", Val4->getReadableName().c_str());
}

TEST(test_uir, test_uir_value_2)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    Value *Ptr1 = new Constant(Type::getInt32PtrTy(CTX), "const_ptr_1");
    printf("Ptr1 ReadableName = %s\n", Ptr1->getReadableName().c_str());

    Value *Ptr2 = new ConstantInt(Type::getInt32PtrTy(CTX), 123);
    printf("Ptr2 ReadableName = %s\n", Ptr2->getReadableName().c_str());

    Value *Ptr3 = new GlobalVariable(Type::getInt32PtrTy(CTX), "global_ptr_1");
    printf("Ptr3 ReadableName = %s\n", Ptr3->getReadableName().c_str());

    Value *Ptr4 = new LocalVariable(Type::getInt32PtrTy(CTX), "local_ptr_1");
    printf("Ptr4 ReadableName = %s\n", Ptr4->getReadableName().c_str());
}

TEST(test_uir, test_uir_value_3)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    Value *Val11 = new GlobalVariable(Type::getInt32Ty(CTX), GlobalVariable::generateOrderedGlobalVarName(CTX));
    printf("Val11 ReadableName = %s\n", Val11->getReadableName().c_str());

    Value *Val12 = new GlobalVariable(Type::getInt32Ty(CTX), GlobalVariable::generateOrderedGlobalVarName(CTX));
    printf("Val12 ReadableName = %s\n", Val12->getReadableName().c_str());

    Value *Val21 = new LocalVariable(Type::getInt32Ty(CTX), LocalVariable::generateOrderedLocalVarName(CTX));
    printf("Val21 ReadableName = %s\n", Val21->getReadableName().c_str());

    Value *Val22 = new LocalVariable(Type::getInt32Ty(CTX), LocalVariable::generateOrderedLocalVarName(CTX));
    printf("Val22 ReadableName = %s\n", Val22->getReadableName().c_str());
}

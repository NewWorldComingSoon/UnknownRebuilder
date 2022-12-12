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

    Value *Val0 = new Value(Type::getInt32Ty(CTX), "var_1");
    printf("Val0 ReadableName = %s\n", Val0->getReadableName().c_str());

    Value *Val1 = new Constant(Type::getInt32Ty(CTX), "const_1");
    printf("Val1 ReadableName = %s\n", Val1->getReadableName().c_str());

    Value *Val2 = new ConstantInt(Type::getInt32Ty(CTX), 123);
    printf("Val2 ReadableName = %s\n", Val2->getReadableName().c_str());

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

    Value *Ptr0 = new Value(Type::getInt32PtrTy(CTX), "var_ptr_1");
    printf("Ptr0 ReadableName = %s\n", Ptr0->getReadableName().c_str());

    Value *Ptr1 = new Constant(Type::getInt32PtrTy(CTX), "const_ptr_1");
    printf("Ptr1 ReadableName = %s\n", Ptr1->getReadableName().c_str());

    Value *Ptr2 = new ConstantInt(Type::getInt32PtrTy(CTX), 123);
    printf("Ptr2 ReadableName = %s\n", Ptr2->getReadableName().c_str());

    Value *Ptr3 = new GlobalVariable(Type::getInt32PtrTy(CTX), "global_ptr_1");
    printf("Ptr3 ReadableName = %s\n", Ptr3->getReadableName().c_str());

    Value *Ptr4 = new LocalVariable(Type::getInt32PtrTy(CTX), "local_ptr_1");
    printf("Ptr4 ReadableName = %s\n", Ptr4->getReadableName().c_str());
}

#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

using namespace uir;

TEST(test_uir, test_uir_type_1)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    auto Ptr8Ty = Type::getInt8PtrTy(CTX);
    printf("Ptr8Ty ElementTypeBits = %d\n", Ptr8Ty->getElementTypeBits());
    printf("Ptr8Ty TypeBits = %d\n", Ptr8Ty->getTypeBits());
    printf("Ptr8Ty PointerBits = %d\n", Ptr8Ty->getPointerBits());

    auto Ptr16Ty = Type::getInt16PtrTy(CTX);
    printf("Ptr16Ty ElementTypeBits = %d\n", Ptr16Ty->getElementTypeBits());
    printf("Ptr16Ty TypeBits = %d\n", Ptr16Ty->getTypeBits());
    printf("Ptr16Ty PointerBits = %d\n", Ptr16Ty->getPointerBits());

    auto Ptr32Ty = Type::getInt32PtrTy(CTX);
    printf("Ptr32Ty ElementTypeBits = %d\n", Ptr32Ty->getElementTypeBits());
    printf("Ptr32Ty TypeBits = %d\n", Ptr32Ty->getTypeBits());
    printf("Ptr32Ty PointerBits = %d\n", Ptr32Ty->getPointerBits());

    auto Ptr64Ty = Type::getInt64PtrTy(CTX);
    printf("Ptr64Ty ElementTypeBits = %d\n", Ptr64Ty->getElementTypeBits());
    printf("Ptr64Ty TypeBits = %d\n", Ptr64Ty->getTypeBits());
    printf("Ptr64Ty PointerBits = %d\n", Ptr64Ty->getPointerBits());
}

TEST(test_uir, test_uir_type_2)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode32);

    auto Ptr8Ty = Type::getInt8PtrTy(CTX);
    printf("Ptr8Ty ElementTypeBits = %d\n", Ptr8Ty->getElementTypeBits());
    printf("Ptr8Ty TypeBits = %d\n", Ptr8Ty->getTypeBits());
    printf("Ptr8Ty PointerBits = %d\n", Ptr8Ty->getPointerBits());

    auto Ptr16Ty = Type::getInt16PtrTy(CTX);
    printf("Ptr16Ty ElementTypeBits = %d\n", Ptr16Ty->getElementTypeBits());
    printf("Ptr16Ty TypeBits = %d\n", Ptr16Ty->getTypeBits());
    printf("Ptr16Ty PointerBits = %d\n", Ptr16Ty->getPointerBits());

    auto Ptr32Ty = Type::getInt32PtrTy(CTX);
    printf("Ptr32Ty ElementTypeBits = %d\n", Ptr32Ty->getElementTypeBits());
    printf("Ptr32Ty TypeBits = %d\n", Ptr32Ty->getTypeBits());
    printf("Ptr32Ty PointerBits = %d\n", Ptr32Ty->getPointerBits());

    // auto Ptr64Ty = Type::getInt64PtrTy(CTX);
    // printf("Ptr64Ty ElementTypeBits = %d\n", Ptr64Ty->getElementTypeBits());
    // printf("Ptr64Ty TypeBits = %d\n", Ptr64Ty->getTypeBits());
    // printf("Ptr64Ty PointerBits = %d\n", Ptr64Ty->getPointerBits());
}

TEST(test_uir, test_uir_type_3)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode64);

    auto Int8Ty = Type::getInt8Ty(CTX);
    printf("Int8Ty TypeBits = %d\n", Int8Ty->getTypeBits());

    auto Int16Ty = Type::getInt16Ty(CTX);
    printf("Int16Ty TypeBits = %d\n", Int16Ty->getTypeBits());

    auto Int32Ty = Type::getInt32Ty(CTX);
    printf("Int32Ty TypeBits = %d\n", Int32Ty->getTypeBits());

    auto Int64Ty = Type::getInt64Ty(CTX);
    printf("Int64Ty TypeBits = %d\n", Int64Ty->getTypeBits());

    auto Int128Ty = Type::getInt128Ty(CTX);
    printf("Int128Ty TypeBits = %d\n", Int128Ty->getTypeBits());
}

TEST(test_uir, test_uir_type_4)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode32);

    auto Int8Ty = Type::getInt8Ty(CTX);
    printf("Int8Ty TypeBits = %d\n", Int8Ty->getTypeBits());

    auto Int16Ty = Type::getInt16Ty(CTX);
    printf("Int16Ty TypeBits = %d\n", Int16Ty->getTypeBits());

    auto Int32Ty = Type::getInt32Ty(CTX);
    printf("Int32Ty TypeBits = %d\n", Int32Ty->getTypeBits());

    auto Int64Ty = Type::getInt64Ty(CTX);
    printf("Int64Ty TypeBits = %d\n", Int64Ty->getTypeBits());

    auto Int128Ty = Type::getInt128Ty(CTX);
    printf("Int128Ty TypeBits = %d\n", Int128Ty->getTypeBits());
}

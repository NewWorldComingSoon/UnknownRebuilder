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
    std::cout << std::format("Ptr8Ty ElementTypeBits = {}", Ptr8Ty->getElementTypeBits()) << std::endl;
    std::cout << std::format("Ptr8Ty TypeBits = {}", Ptr8Ty->getTypeBits()) << std::endl;
    std::cout << std::format("Ptr8Ty PointerBits = {}", Ptr8Ty->getPointerBits()) << std::endl;

    auto Ptr16Ty = Type::getInt16PtrTy(CTX);
    std::cout << std::format("Ptr16Ty ElementTypeBits = {}", Ptr16Ty->getElementTypeBits()) << std::endl;
    std::cout << std::format("Ptr16Ty TypeBits = {}", Ptr16Ty->getTypeBits()) << std::endl;
    std::cout << std::format("Ptr16Ty PointerBits = {}", Ptr16Ty->getPointerBits()) << std::endl;

    auto Ptr32Ty = Type::getInt32PtrTy(CTX);
    std::cout << std::format("Ptr16Ty ElementTypeBits = {}", Ptr32Ty->getElementTypeBits()) << std::endl;
    std::cout << std::format("Ptr16Ty TypeBits = {}", Ptr32Ty->getTypeBits()) << std::endl;
    std::cout << std::format("Ptr16Ty PointerBits = {}", Ptr32Ty->getPointerBits()) << std::endl;

    auto Ptr64Ty = Type::getInt64PtrTy(CTX);
    std::cout << std::format("Ptr16Ty ElementTypeBits = {}", Ptr64Ty->getElementTypeBits()) << std::endl;
    std::cout << std::format("Ptr16Ty TypeBits = {}", Ptr64Ty->getTypeBits()) << std::endl;
    std::cout << std::format("Ptr16Ty PointerBits = {}", Ptr64Ty->getPointerBits()) << std::endl;
}

TEST(test_uir, test_uir_type_2)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode32);

    auto Ptr8Ty = Type::getInt8PtrTy(CTX);
    std::cout << std::format("Ptr8Ty ElementTypeBits = {}", Ptr8Ty->getElementTypeBits()) << std::endl;
    std::cout << std::format("Ptr8Ty TypeBits = {}", Ptr8Ty->getTypeBits()) << std::endl;
    std::cout << std::format("Ptr8Ty PointerBits = {}", Ptr8Ty->getPointerBits()) << std::endl;

    auto Ptr16Ty = Type::getInt16PtrTy(CTX);
    std::cout << std::format("Ptr16Ty ElementTypeBits = {}", Ptr16Ty->getElementTypeBits()) << std::endl;
    std::cout << std::format("Ptr16Ty TypeBits = {}", Ptr16Ty->getTypeBits()) << std::endl;
    std::cout << std::format("Ptr16Ty PointerBits = {}", Ptr16Ty->getPointerBits()) << std::endl;

    auto Ptr32Ty = Type::getInt32PtrTy(CTX);
    std::cout << std::format("Ptr32Ty ElementTypeBits = {}", Ptr32Ty->getElementTypeBits()) << std::endl;
    std::cout << std::format("Ptr32Ty TypeBits = {}", Ptr32Ty->getTypeBits()) << std::endl;
    std::cout << std::format("Ptr32Ty PointerBits = {}", Ptr32Ty->getPointerBits()) << std::endl;

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
    std::cout << std::format("Int8Ty TypeBits = {}", Int8Ty->getTypeBits()) << std::endl;

    auto Int16Ty = Type::getInt16Ty(CTX);
    std::cout << std::format("Int16Ty TypeBits = {}", Int16Ty->getTypeBits()) << std::endl;

    auto Int32Ty = Type::getInt32Ty(CTX);
    std::cout << std::format("Int32Ty TypeBits = {}", Int32Ty->getTypeBits()) << std::endl;

    auto Int64Ty = Type::getInt64Ty(CTX);
    std::cout << std::format("Int64Ty TypeBits = {}", Int64Ty->getTypeBits()) << std::endl;

    auto Int128Ty = Type::getInt128Ty(CTX);
    std::cout << std::format("Int128Ty TypeBits = {}", Int128Ty->getTypeBits()) << std::endl;
}

TEST(test_uir, test_uir_type_4)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode32);

    auto Int8Ty = Type::getInt8Ty(CTX);
    std::cout << std::format("Int8Ty TypeBits = {}", Int8Ty->getTypeBits()) << std::endl;

    auto Int16Ty = Type::getInt16Ty(CTX);
    std::cout << std::format("Int16Ty TypeBits = {}", Int16Ty->getTypeBits()) << std::endl;

    auto Int32Ty = Type::getInt32Ty(CTX);
    std::cout << std::format("Int32Ty TypeBits = {}", Int32Ty->getTypeBits()) << std::endl;

    auto Int64Ty = Type::getInt64Ty(CTX);
    std::cout << std::format("Int64Ty TypeBits = {}", Int64Ty->getTypeBits()) << std::endl;

    auto Int128Ty = Type::getInt128Ty(CTX);
    std::cout << std::format("Int128Ty TypeBits = {}", Int128Ty->getTypeBits()) << std::endl;
}

TEST(test_uir, test_uir_type_5)
{
    Context CTX;
    CTX.setArch(Context::ArchX86);
    CTX.setMode(Context::Mode32);

    auto GV = GlobalVariable::get(Type::getInt8Ty(CTX));
    std::vector<uint8_t> Vec;
    Vec.push_back(0xcc);
    Vec.push_back(0x90);
    auto GA = GlobalArray<>::get(CTX, Type::getInt8Ty(CTX), Vec);

    if (auto TestGV = dynamic_cast<GlobalVariable *>(GV))
    {
        std::cout << "TestGV!!!" << std::endl;
    }

    if (auto TestGV2 = dynamic_cast<GlobalVariable *>(GA))
    {
        std::cout << "TestGV2!!!" << std::endl;
    }

    if (auto TestGA = dynamic_cast<GlobalArray<> *>(GV))
    {
        std::cout << "TestGA!!!" << std::endl;
    }

    if (auto TestGA2 = dynamic_cast<GlobalArray<> *>(GA))
    {
        std::cout << "TestGV2!!!" << std::endl;
    }

    for (size_t i = 0; i < GA->getGlobalArray().size(); ++i)
    {
        std::cout << std::format(
                         "GA->getGlobalArray({}) = {}",
                         i,
                         "0x" + unknown::APInt(8, GA->getGlobalArray()[i]).toString(16, false))
                  << std::endl;
    }
}

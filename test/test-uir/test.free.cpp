#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

using namespace uir;

TEST(test_uir, test_uir_free_1)
{
    // 1.
    {
        Context CTX;
        CTX.setArch(Context::Arch::ArchX86);
        CTX.setMode(Context::Mode::Mode64);
    }

    std::cout << "--------------------bp-----------------------\n";
}
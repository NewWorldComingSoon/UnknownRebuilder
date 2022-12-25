
#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

#include <UnknownUtils/unknown/ADT/APInt.h>

#include <UnknownUtils/unknown/Support/raw_ostream.h>
#include <UnknownUtils/unknown/Support/FileSystem.h>

TEST(test_uir, test_uir_utils_1)
{
    std::error_code EC;
    unknown::raw_fd_ostream Out(UNKNOWN_REBUILDER_SRC_DIR R"(/test_uir_utils_1.TXT)", EC, unknown::sys::fs::F_None);
    Out << "0x" << unknown::APInt(32, 0x401B00).toString(16, false);
    Out << "\n";
    Out << unknown::APInt(32, 0x401B0C).toString(10, false);
    Out.close();
}

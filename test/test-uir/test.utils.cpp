
#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

#include <UnknownUtils/unknown/Support/raw_ostream.h>
#include <UnknownUtils/unknown/Support/FileSystem.h>

TEST(test_uir, test_uir_utils_1)
{
    std::error_code EC;
    unknown::raw_fd_ostream Out(UNKNOWN_REBUILDER_SRC_DIR R"(/test_uir_utils_1.TXT)", EC, unknown::sys::fs::F_None);
    Out << "0x" << unknown::hexdigit(11);
    Out.close();
}


#include <UnknownIR.h>
#include <gtest/gtest.h>
#include <format>
#include <iostream>

#include <UnknownUtils/unknown/ADT/APInt.h>

#include <UnknownUtils/unknown/Support/raw_ostream.h>
#include <UnknownUtils/unknown/Support/FileSystem.h>

#include <UnknownUtils/unknown/Symbol/SymbolParser.h>

TEST(test_uir, test_uir_utils_1)
{
    // std::error_code EC;
    //  unknown::raw_fd_ostream Out(UNKNOWN_REBUILDER_SRC_DIR R"(/test_uir_utils_1.TXT)", EC, unknown::sys::fs::F_None);
    unknown::outs() << "0x" << unknown::APInt(32, 0x401B00).toString(16, false);
    unknown::outs() << "\n";
    unknown::outs() << unknown::APInt(32, 0x401B0C).toString(10, false);
    unknown::outs() << "\n";
    // Out.close();
}

TEST(test_uir, test_uir_utils_2)
{
    auto SymParserPdb = unknown::CreateSymbolParser(true);
    if (SymParserPdb)
    {
        auto succ = SymParserPdb->ParseFunctionSymbols(UNKNOWN_REBUILDER_SRC_DIR R"(\sample\pe-x64\Project12.pdb)");
        if (succ)
        {
            for (auto &Sym : SymParserPdb->getFunctionSymbols())
            {
                if (Sym.hasGuardCF)
                {
                    std::cout << std::format("rva:0x{:X} name:{} size:0x{:X}", Sym.rva, Sym.name, Sym.size) << "\n";
                }
            }
        }
    }
}

TEST(test_uir, test_uir_utils_3)
{
    auto SymParserMap = unknown::CreateSymbolParser(false);
    if (SymParserMap)
    {
        auto succ = SymParserMap->ParseFunctionSymbols(UNKNOWN_REBUILDER_SRC_DIR R"(\sample\pe-x64\Project12.map)");
        if (succ)
        {
            for (auto &Sym : SymParserMap->getFunctionSymbols())
            {
                // std::cout << std::format("rva:0x{:X} name:{} size:0x{:X}", Sym.rva, Sym.name, Sym.size) << "\n";
            }
        }
    }
}

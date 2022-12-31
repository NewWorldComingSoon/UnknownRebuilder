#include <iostream>
#include <memory>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <format>

#include <LIEF/PE.hpp>
#include <gtest/gtest.h>

using namespace LIEF::PE;

TEST(test_lief, test_lief_1)
{
    std::unique_ptr<Binary> binary{Parser::parse(UNKNOWN_REBUILDER_SRC_DIR R"(/sample/pe-x64/Project12.exe)")};

    Section newSec = Section(".te2");
    std::vector<uint8_t> vec = {0xcc};
    newSec.content(vec);
    binary->add_section(newSec, PE_SECTION_TYPES::TEXT);

    Builder builder{*binary};

    builder.build_imports(false).patch_imports(false).build_tls(false).build_resources(false);

    builder.build();
    builder.write(UNKNOWN_REBUILDER_SRC_DIR R"(/sample/pe-x64/Project12.rebuild.exe)");
    std::cout << binary->name() << '\n';
}

TEST(test_lief, test_lief_2)
{
    std::unique_ptr<Binary> binary{Parser::parse(UNKNOWN_REBUILDER_SRC_DIR R"(/sample/pe-x64/Project12.exe)")};

    Section newSec = Section(".te22");
    binary->add_section(newSec, PE_SECTION_TYPES::TEXT);

    Builder builder{*binary};

    builder.build();
    builder.write(UNKNOWN_REBUILDER_SRC_DIR R"(/sample/pe-x64/Project12.rebuild2.exe)");
    std::cout << binary->name() << '\n';
}
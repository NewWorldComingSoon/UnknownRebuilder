#include <iostream>
#include <memory>
#include <fstream>
#include <algorithm>
#include <iterator>
#include <format>

#include <gtest/gtest.h>
#include <UnknownUtils/unknown/tinyxml2/tinyxml2.h>
#include <UnknownUtils/unknown/Support/raw_ostream.h>

using namespace unknown;

TEST(test_xml, test_xml_1)
{
    XMLDocument doc;
    auto ret = doc.LoadFile(UNKNOWN_REBUILDER_SRC_DIR R"(/sample/xml/test1.xml)");
    if (ret == XML_SUCCESS)
    {
        std::cout << "XML_SUCCESS" << '\n';
    }
    else
    {
        std::cout << "XML_ERROR_FILE_NOT_FOUND" << '\n';
        return;
    }

    auto module_root = doc.RootElement();
    if (module_root == nullptr)
    {
        std::cout << "module_root is nullptr" << '\n';
        return;
    }

    auto module_name = module_root->Attribute("name");
    std::cout << "module_name = " << module_name << std::endl;

    for (XMLElement *currenteleElement = module_root->FirstChildElement("gv"); currenteleElement;
         currenteleElement = currenteleElement->NextSiblingElement("gv"))
    {
        auto gv_addr = currenteleElement->Attribute("addr");
        std::cout << "gv_addr = " << gv_addr << "\t";
        auto gv_name = currenteleElement->Attribute("name");
        std::cout << "gv_name = " << gv_name << std::endl;
    }

    for (XMLElement *currenteleElement = module_root->FirstChildElement("f"); currenteleElement;
         currenteleElement = currenteleElement->NextSiblingElement("f"))
    {
        auto f_range = currenteleElement->Attribute("range");
        std::cout << "f_range = " << f_range << "\t";
        auto f_name = currenteleElement->Attribute("name");
        std::cout << "f_name = " << f_name << std::endl;
    }

    {
        XMLPrinter printer;
        printer.OpenElement("module");
        printer.PushAttribute("name", "mod1");

        printer.OpenElement("gv");
        printer.PushAttribute("addr", "0x12345678");
        printer.CloseElement();

        printer.OpenElement("gv");
        printer.PushAttribute("addr", "0x123455");
        printer.CloseElement();

        printer.OpenElement("f");
        printer.PushAttribute("range", "0x1000-0x2000");
        printer.PushAttribute("name", "function.func1");
        printer.CloseElement();

        printer.CloseElement();
        unknown::outs() << printer.CStr();
    }
}

TEST(test_xml, test_xml_2)
{
    XMLDocument doc;
    auto ret = doc.LoadFile(UNKNOWN_REBUILDER_SRC_DIR R"(/sample/xml/testcfg.xml)");
    if (ret == XML_SUCCESS)
    {
        std::cout << "XML_SUCCESS" << '\n';
    }
    else
    {
        std::cout << "XML_ERROR_FILE_NOT_FOUND" << '\n';
        return;
    }

    auto config_root = doc.RootElement();
    if (config_root == nullptr)
    {
        std::cout << "config is nullptr" << '\n';
        return;
    }

    auto config_name = config_root->Attribute("name");
    std::cout << "config_name = " << config_name << std::endl;

    for (XMLElement *currenteleElement = config_root->FirstChildElement("f"); currenteleElement;
         currenteleElement = currenteleElement->NextSiblingElement("f"))
    {
        auto f_name = currenteleElement->Attribute("name");
        std::cout << "f_name = " << f_name << std::endl;

        for (int i = 1; 1; ++i)
        {
            auto attri_i = std::string("attribute") + std::to_string(i);
            auto attri = currenteleElement->Attribute(attri_i.c_str());
            if (attri)
            {
                std::cout << "attri = " << attri << std::endl;
            }
            else
            {
                break;
            }
        }
    }
}

#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <memory>

namespace unknown {

class SymbolParser
{
public:
    struct FunctionSymbol
    {
        std::string name;
        uint32_t rva;
        uint32_t size;
    };

protected:
    std::vector<FunctionSymbol> mFunctionSymbols;
    uint64_t mImageBase;

public:
    SymbolParser() : mImageBase(0) {}
    ~SymbolParser() = default;

public:
    // Get/Set
    uint64_t getImageBase() const { return mImageBase; }
    void setImageBase(uint64_t imageBase) { mImageBase = imageBase; }
    std::vector<FunctionSymbol> &getFunctionSymbols() { return mFunctionSymbols; }

public:
    // Itereter
    using iterator = std::vector<FunctionSymbol>::iterator;
    using const_iterator = std::vector<FunctionSymbol>::const_iterator;
    using reverse_iterator = std::vector<FunctionSymbol>::reverse_iterator;
    using const_reverse_iterator = std::vector<FunctionSymbol>::const_reverse_iterator;

    iterator begin() { return mFunctionSymbols.begin(); }
    const_iterator begin() const { return mFunctionSymbols.cbegin(); }
    iterator end() { return mFunctionSymbols.end(); }
    const_iterator end() const { return mFunctionSymbols.cend(); }

    reverse_iterator rbegin() { return mFunctionSymbols.rbegin(); }
    const_reverse_iterator rbegin() const { return mFunctionSymbols.crbegin(); }
    reverse_iterator rend() { return mFunctionSymbols.rend(); }
    const_reverse_iterator rend() const { return mFunctionSymbols.crend(); }
};

} // namespace unknown
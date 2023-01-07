#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <memory>

#include "unknown/ADT/StringRef.h"

namespace unknown {

class SymbolParser
{
public:
    struct CommonSymbol
    {
        std::string name = "";
        uint32_t rva = 0;
    };

    struct FunctionSymbol : CommonSymbol
    {
        uint32_t size = 0; // function size

        uint32_t cbFrame = 0;    // count of bytes of total frame of procedure
        uint32_t cbPad = 0;      // count of bytes of padding in the frame
        uint32_t offPad = 0;     // offset (relative to frame poniter) to where
                                 //  padding starts
        uint32_t cbSaveRegs = 0; // count of bytes of callee save registers
        uint32_t offExHdlr = 0;  // offset of exception handler
        uint16_t sectExHdlr = 0; // section id of exception handler

        bool hasAlloca = false;         // function uses _alloca()
        bool hasSetJmp = false;         // function uses setjmp()
        bool hasLongJmp = false;        // function uses longjmp()
        bool hasInlAsm = false;         // function uses inline asm
        bool hasEH = false;             // function has EH states
        bool hasSEH = false;            // function has SEH
        bool hasNaked = false;          // function is __declspec(naked)
        bool hasSecurityChecks = false; // function has buffer security check introduced by /GS.
        bool hasAsyncEH = false;        // function compiled with /EHa
        bool hasWasInlined = false;     // function was inlined within another function
        bool hasGSCheck = false;        // function is __declspec(strict_gs_check)
        bool hasSafeBuffers = false;    // function is __declspec(safebuffers)
        bool hasOptSpeed = false;       // Did we optimize for speed?
        bool hasGuardCF = false;        // function contains CFG checks (and no write checks)
    };

protected:
    std::vector<CommonSymbol> mCommonSymbols;
    std::vector<FunctionSymbol> mFunctionSymbols;
    uint64_t mImageBase;

public:
    SymbolParser() : mImageBase(0) {}
    ~SymbolParser() = default;

public:
    // Parser
    virtual bool ParseCommonSymbols(StringRef SymFilePath) = 0;
    virtual bool ParseFunctionSymbols(StringRef SymFilePath) = 0;

public:
    // Get/Set
    uint64_t getImageBase() const { return mImageBase; }
    void setImageBase(uint64_t imageBase) { mImageBase = imageBase; }
    std::vector<FunctionSymbol> &getFunctionSymbols() { return mFunctionSymbols; }
    std::vector<CommonSymbol> &getAllSymbols() { return mCommonSymbols; }
};

////////////////////////////////////////////////////////////////////////////////////////
//// Function
std::unique_ptr<SymbolParser>
CreateSymbolParserForPE(bool UsePDB = true);

} // namespace unknown
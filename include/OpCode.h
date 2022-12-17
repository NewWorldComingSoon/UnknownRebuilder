#pragma once
#include <string>
#include <cstdint>

namespace uir {
#define GET_OPCODE_NAME(Name) (#Name)

enum OpCode : uint8_t
{
    // Binary Operators
    Add,
    Sub,

    // Terminator
    Ret,
    RetIMM,

    // Unknown
    Unknown
};

struct OpCodeComponent
{
    std::string mName;
    OpCode mOpCode;
    uint32_t mNumberOfOperands;
    bool mHasEFlags;
};

__declspec(selectany) OpCodeComponent gOpCodeComponent[] = {
    // Binary Operators
    {GET_OPCODE_NAME(Add), Add, 3, true},
    {GET_OPCODE_NAME(Sub), Sub, 3, true},

    // Terminator
    {GET_OPCODE_NAME(Ret), Ret, 0, false},
    {GET_OPCODE_NAME(RetIMM), RetIMM, 1, false},

    // Unknown
    {GET_OPCODE_NAME(Unknown), Unknown, 0, false},
};

#undef GET_OPCODE_NAME
} // namespace uir

#pragma once
#include <cstdint>
#include <string>
#include <array>

namespace uir {

enum class OpCodeID : uint8_t
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
    OpCodeID mOpCodeID;
    std::string mOpCodeName;
    uint32_t mNumberOfOperands;
    bool mHasEFlags;
};

const OpCodeComponent GlobalOpCodeComponents[] = {
    // Binary Operators
    {OpCodeID::Add, "Add", 3, true},
    {OpCodeID::Sub, "Sub", 3, true},

    // Terminator
    {OpCodeID::Ret, "Ret", 0, false},
    {OpCodeID::RetIMM, "RetIMM", 1, false},

    // Unknown
    {OpCodeID::Unknown, "Unknown", 0, false},
};

} // namespace uir

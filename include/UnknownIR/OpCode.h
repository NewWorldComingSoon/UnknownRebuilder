#pragma once
#include <cstdint>
#include <string>
#include <array>

namespace uir {

enum class OpCodeID : uint8_t
{
    // Binary operators instructions
    Add,
    Sub,

    // Bitwise instructions
    Xor,
    Or,
    And,
    Not,

    // Terminator instructions
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

// clang-format off
const OpCodeComponent GlobalOpCodeComponents[] = {
    // Binary operators instructions
        // op3 = op1 + op2
    {   OpCodeID::Add,         "Add",      3,      true    },
        // op3 = op1 - op2
    {   OpCodeID::Sub,         "Sub",      3,      true    },

    // Bitwise instructions
        // op3 = op1 ^ op2
    {   OpCodeID::Xor,         "Xor",      3,      true    },
        // op3 = op1 | op2
    {   OpCodeID::Or,          "Or",       3,      true    },
        // op3 = op1 & op2
    {   OpCodeID::And,         "And",      3,      true    },
        // op2 = ~op1
    {   OpCodeID::Not,         "Not",      2,      false   },
	
    // Terminator instructions
        // ret
    {   OpCodeID::Ret,         "Ret",      0,      false   },
        // ret imm
    {   OpCodeID::RetIMM,      "RetIMM",   1,      false   },

        // Unknown
    {   OpCodeID::Unknown,     "Unknown",  0,      false   },
};
// clang-format on

} // namespace uir

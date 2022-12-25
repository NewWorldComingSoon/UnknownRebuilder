#pragma once
#include <cstdint>
#include <vector>

#include <UnknownUtils/unknown/ADT/StringRef.h>

namespace uir {

enum class OpCodeID : uint8_t
{
    // Data/Memory instructions
    Load,
    Store,

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
    unknown::StringRef mOpCodeName;
    uint32_t mNumberOfOperands;
    bool mHasFlags;
};

// clang-format off
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Data/Memory instructions
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// op2 = load op1
const OpCodeComponent LoadComponent       = {    OpCodeID::Load,        "load",         2,     false};

// store op1, op2
const OpCodeComponent StoreComponent      = {    OpCodeID::Store,       "store",        2,     false};

// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Binary operators instructions
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// op3 = op1 + op2
const OpCodeComponent AddComponent        = {    OpCodeID::Add,         "add",          3,      true};

// op3 = op1 - op2
const OpCodeComponent SubComponent        = {    OpCodeID::Sub,         "sub",          3,      true};


// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Bitwise instructions
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// op3 = op1 ^ op2
const OpCodeComponent XorComponent        = {    OpCodeID::Xor,         "xor",          3,      true};

// op3 = op1 | op2
const OpCodeComponent OrComponent         = {    OpCodeID::Or,          "or",           3,      true};

// op3 = op1 & op2
const OpCodeComponent AndComponent        = {    OpCodeID::And,         "and",          3,      true};

// op2 = ~op1
const OpCodeComponent NotComponent        = {    OpCodeID::Not,         "not",          2,      false};


// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Terminator instructions
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// ret
const OpCodeComponent RetComponent        = {    OpCodeID::Ret,         "ret",          0,      false};

// ret imm
const OpCodeComponent RetIMMComponent     = {    OpCodeID::RetIMM,      "ret.imm",      1,      false};


// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
// Unknown
// ///////////////////////////////////////////////////////////////////////////////////////////////////////////////////////
const OpCodeComponent UnknownComponent    = {    OpCodeID::Unknown,     "unknown",      0,      false};
// clang-format on

} // namespace uir

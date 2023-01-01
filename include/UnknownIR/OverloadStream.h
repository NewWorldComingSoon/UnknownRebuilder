#pragma once
#include <UnknownIR/Instruction.h>
#include <UnknownIR/Module.h>
#include <UnknownIR/BasicBlock.h>
#include <UnknownIR/Function.h>

namespace uir {

/////////////////////////////////////////////////////////////////////
// Overload value stream
inline unknown::raw_ostream &
operator<<(unknown::raw_ostream &OS, const Value &V)
{
    V.print(OS);
    return OS;
}

/////////////////////////////////////////////////////////////////////
// Overload module stream
inline unknown::raw_ostream &
operator<<(unknown::raw_ostream &OS, const Module &M)
{
    M.print(OS);
    return OS;
}

} // namespace uir
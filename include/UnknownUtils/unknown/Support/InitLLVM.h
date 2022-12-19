//===- InitLLVM.h -----------------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "unknown/ADT/SmallVector.h"
#include "unknown/Support/Allocator.h"
#include "unknown/Support/PrettyStackTrace.h"

// The main() functions in typical LLVM tools start with InitLLVM which does
// the following one-time initializations:
//
//  1. Setting up a signal handler so that pretty stack trace is printed out
//     if a process crashes.
//
//  2. If running on Windows, obtain command line arguments using a
//     multibyte character-aware API and convert arguments into UTF-8
//     encoding, so that you can assume that command line arguments are
//     always encoded in UTF-8 on any platform.
//
// InitLLVM calls llvm_shutdown() on destruction, which cleans up
// ManagedStatic objects.
namespace unknown {
class InitLLVM
{
public:
    InitLLVM(int &Argc, const char **&Argv);
    InitLLVM(int &Argc, char **&Argv) : InitLLVM(Argc, const_cast<const char **&>(Argv)) {}

    ~InitLLVM();

private:
    BumpPtrAllocator Alloc;
    SmallVector<const char *, 0> Args;
    PrettyStackTraceProgram StackPrinter;
};
} // namespace unknown

#endif

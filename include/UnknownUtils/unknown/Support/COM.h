//===- llvm/Support/COM.h ---------------------------------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
/// \file
///
/// Provides a library for accessing COM functionality of the Host OS.
///
//===----------------------------------------------------------------------===//

#pragma once

namespace unknown {
namespace sys {

enum class COMThreadingMode
{
    SingleThreaded,
    MultiThreaded
};

class InitializeCOMRAII
{
public:
    explicit InitializeCOMRAII(COMThreadingMode Threading, bool SpeedOverMemory = false);
    ~InitializeCOMRAII();

private:
    InitializeCOMRAII(const InitializeCOMRAII &) = delete;
    void operator=(const InitializeCOMRAII &) = delete;
};
} // namespace sys
} // namespace unknown

#endif

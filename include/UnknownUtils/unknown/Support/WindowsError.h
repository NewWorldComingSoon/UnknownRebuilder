//===-- WindowsError.h - Support for mapping windows errors to posix-------===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#pragma once

#include <system_error>

namespace unknown {
std::error_code
mapWindowsError(unsigned EV);
}

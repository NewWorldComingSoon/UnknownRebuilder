//===-- llvm/Support/TarWriter.h - Tar archive file creator -----*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "unknown/ADT/StringRef.h"
#include "unknown/ADT/StringSet.h"
#include "unknown/Support/Error.h"
#include "unknown/Support/raw_ostream.h"

namespace unknown {
class TarWriter
{
public:
    static Expected<std::unique_ptr<TarWriter>> create(StringRef OutputPath, StringRef BaseDir);

    void append(StringRef Path, StringRef Data);

private:
    TarWriter(int FD, StringRef BaseDir);
    raw_fd_ostream OS;
    std::string BaseDir;
    StringSet<> Files;
};
} // namespace unknown

#endif

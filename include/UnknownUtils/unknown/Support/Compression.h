//===-- llvm/Support/Compression.h ---Compression----------------*- C++ -*-===//
//
//                     The LLVM Compiler Infrastructure
//
// This file is distributed under the University of Illinois Open Source
// License. See LICENSE.TXT for details.
//
//===----------------------------------------------------------------------===//
//
// This file contains basic functions for compression/uncompression.
//
//===----------------------------------------------------------------------===//

#pragma once

#include "unknown/Support/DataTypes.h"

namespace unknown {
template <typename T>
class SmallVectorImpl;
class Error;
class StringRef;

namespace zlib {

static constexpr int NoCompression = 0;
static constexpr int BestSpeedCompression = 1;
static constexpr int DefaultCompression = 6;
static constexpr int BestSizeCompression = 9;

bool
isAvailable();

Error
compress(StringRef InputBuffer, SmallVectorImpl<char> &CompressedBuffer, int Level = DefaultCompression);

Error
uncompress(StringRef InputBuffer, char *UncompressedBuffer, size_t &UncompressedSize);

Error
uncompress(StringRef InputBuffer, SmallVectorImpl<char> &UncompressedBuffer, size_t UncompressedSize);

uint32_t
crc32(StringRef Buffer);

} // End of namespace zlib

} // namespace unknown

#endif

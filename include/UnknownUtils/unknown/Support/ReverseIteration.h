#pragma once

#include "unknown/Config/abi-breaking.h"
#include "unknown/Support/PointerLikeTypeTraits.h"

namespace unknown {

template <class T = void *>
bool
shouldReverseIterate()
{
#if LLVM_ENABLE_REVERSE_ITERATION
    return detail::IsPointerLike<T>::value;
#else
    return false;
#endif
}

} // namespace unknown

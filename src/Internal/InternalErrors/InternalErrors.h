#pragma once

namespace uir {

void
uir_unreachable_internal(const char *msg = nullptr, const char *file = nullptr, unsigned line = 0);

} // namespace uir

#ifndef NDEBUG
#    define uir_unreachable(msg) ::uir::uir_unreachable_internal(msg, __FILE__, __LINE__)
#else
#    define uir_unreachable(msg) ::uir::uir_unreachable_internal()
#endif

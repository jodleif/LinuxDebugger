#pragma once

namespace dbg {
#ifdef _NDEBUG
constexpr bool debug{ true };
#else
constexpr bool debug{ false };
#endif
}

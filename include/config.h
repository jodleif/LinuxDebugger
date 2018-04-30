#pragma once

namespace dbg {
#ifdef NDEBUG
constexpr bool debug{ false };
#else
constexpr bool debug{ true };
#endif
}

cmake_minimum_required(VERSION 3.8)
set(CMAKE_CXX_STANDARD 17)
project(LinuxDebugger)



set(GCC_WARNINGS "-pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Wno-unused")
set(CLANG_WARNINGS "-Weverything -Wno-c++98-support")
set(CMAKE_CXX_FLAGS "-march=native -mtune=native ${GCC_WARNINGS}")
set(CMAKE_CXX_FLAGS_DEBUG "-ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(HDR "include/debugger.h" "include/breakpoint.h" "include/registry.h" "include/config.h")
set(SRC "src/main.cpp" "src/debugger.cpp" "linenoise/linenoise.c" "src/breakpoint.cpp" "src/registry.cpp")
include_directories(linenoise)
include_directories(include)
add_executable(${PROJECT_NAME} ${HDR} ${SRC})
target_link_libraries(${PROJECT_NAME} explain)

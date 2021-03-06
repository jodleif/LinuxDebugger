cmake_minimum_required(VERSION 3.8)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_C_STANDARD 11)
project(LinuxDebugger)



set(GCC_WARNINGS "-fdiagnostics-color -pedantic -Wall -Wextra -Wcast-align -Wcast-qual -Wctor-dtor-privacy -Wdisabled-optimization -Wformat=2 -Winit-self -Wlogical-op -Wmissing-declarations -Wmissing-include-dirs -Wnoexcept -Wold-style-cast -Woverloaded-virtual -Wredundant-decls -Wshadow -Wsign-conversion -Wsign-promo -Wstrict-null-sentinel -Wstrict-overflow=5 -Wswitch-default -Wundef -Wno-unused")
set(CLANG_WARNINGS "-Weverything -Wno-c++98-support")
set(CMAKE_CXX_FLAGS "-march=native -mtune=native ${GCC_WARNINGS}")
set(CMAKE_CXX_FLAGS_DEBUG "-ggdb")
set(CMAKE_CXX_FLAGS_RELEASE "-O3")

set(HDR "include/debugger.h" "include/breakpoint.h" "include/registry.h" "include/config.h" "include/symbol_type.h" "include/elfin_ext.h")
set(SRC "src/main.cpp" "src/debugger.cpp" "submodules/linenoise/linenoise.c" "src/breakpoint.cpp" "src/registry.cpp" "src/elfin_ext.cpp")

include_directories(include)
#ignore warnings for libraries
include_directories(SYSTEM submodules/libelfin submodules/linenoise)

add_executable(${PROJECT_NAME} ${HDR} ${SRC})

add_custom_target(
    libelfin
    COMMAND make
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}/submodules/libelfin
    BYPRODUCTS ${PROJECT_SOURCE_DIR}/submodules/libelfin/dwarf/libdwarf++.so ${PROJECT_SOURCE_DIR}/submodules/libelfin/elf/libelf++.so
)
add_dependencies(${PROJECT_NAME} libelfin)
target_link_libraries(${PROJECT_NAME} explain
                                      ${PROJECT_SOURCE_DIR}/submodules/libelfin/dwarf/libdwarf++.so
                                      ${PROJECT_SOURCE_DIR}/submodules/libelfin/elf/libelf++.so)

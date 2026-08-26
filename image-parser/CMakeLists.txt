cmake_minimum_required(VERSION 3.20)
project(forensicfs_parser LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

find_path(TSK_INCLUDE_DIR tsk/libtsk.h REQUIRED)
find_library(TSK_LIBRARY tsk REQUIRED)

add_library(forensicfs_engine src/forensic_engine.cpp)
target_include_directories(forensicfs_engine PUBLIC include ${TSK_INCLUDE_DIR})
target_link_libraries(forensicfs_engine PUBLIC ${TSK_LIBRARY})
target_compile_options(forensicfs_engine PRIVATE -Wall -Wextra -Wpedantic -Werror)

add_executable(forensicfs-parser src/main.cpp)
target_link_libraries(forensicfs-parser PRIVATE forensicfs_engine)

enable_testing()
add_executable(parser-signature-test tests/signature_test.cpp)
target_link_libraries(parser-signature-test PRIVATE forensicfs_engine)
add_test(NAME parser-signature-test COMMAND parser-signature-test)

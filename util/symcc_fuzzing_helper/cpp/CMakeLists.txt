cmake_minimum_required(VERSION 3.10)
project(SymccFuzzingHelperCpp LANGUAGES CXX)

add_executable(symcc_fuzzing_helper_cpp main.cpp helper.cpp)
target_compile_features(symcc_fuzzing_helper_cpp PRIVATE cxx_std_17)
set_target_properties(symcc_fuzzing_helper_cpp PROPERTIES CXX_EXTENSIONS OFF)
target_compile_options(symcc_fuzzing_helper_cpp PRIVATE -Wall -Wextra -Wpedantic)
find_package(Threads REQUIRED)
target_link_libraries(symcc_fuzzing_helper_cpp PRIVATE Threads::Threads)
if (CMAKE_CXX_COMPILER_ID STREQUAL "GNU" AND CMAKE_CXX_COMPILER_VERSION VERSION_LESS 9)
    target_link_libraries(symcc_fuzzing_helper_cpp PRIVATE stdc++fs)
endif ()
install(TARGETS symcc_fuzzing_helper_cpp RUNTIME DESTINATION bin)

include(CTest)
if (BUILD_TESTING)
    find_program(HELPER_CPP_PYTHON NAMES python3)
    if (HELPER_CPP_PYTHON)
        add_test(NAME helper_cpp_parallel
            COMMAND "${HELPER_CPP_PYTHON}" "${CMAKE_CURRENT_SOURCE_DIR}/tests/integration.py"
                    "$<TARGET_FILE:symcc_fuzzing_helper_cpp>")
        set_tests_properties(helper_cpp_parallel PROPERTIES TIMEOUT 90)
    endif ()
endif ()

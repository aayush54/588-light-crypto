cmake_minimum_required(VERSION 3.20)

project(588-light-crypto)

macro(get_all_targets_recursive targets dir)
    get_property(subdirectories DIRECTORY ${dir} PROPERTY SUBDIRECTORIES)
    foreach(subdir ${subdirectories})
        get_all_targets_recursive(${targets} ${subdir})
    endforeach()

    get_property(current_targets DIRECTORY ${dir} PROPERTY BUILDSYSTEM_TARGETS)
    list(APPEND ${targets} ${current_targets})
endmacro()

function(get_all_targets var)
    set(targets)
    get_all_targets_recursive(targets ${CMAKE_CURRENT_SOURCE_DIR})
    set(${var} ${targets} PARENT_SCOPE)
endfunction()

add_executable(test src/test.cpp)
target_compile_features(test PRIVATE cxx_std_20)

add_subdirectory(ascon-c)


get_all_targets(all_targets)

foreach(target ${all_targets})
message(${target})
    get_target_property(target_type ${target} TYPE)
    if(NOT(target_type STREQUAL "EXECUTABLE"))
        target_link_libraries(test ${target})
    endif()
endforeach()
#
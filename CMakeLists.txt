cmake_minimum_required(VERSION 3.20)

project(588-light-crypto)

if(MSVC)
	if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
    	add_definitions(/MP)				# parallelize each target, unless Ninja is the generator
	endif()
endif()

add_executable(test src/test.cpp)
target_compile_features(test PRIVATE cxx_std_20)

add_subdirectory(ascon-c EXCLUDE_FROM_ALL)

set(WITH_APPS OFF CACHE INTERNAL "")
add_subdirectory(openssl-cmake EXCLUDE_FROM_ALL)

target_link_libraries(test PUBLIC ${target} crypto_aead_ascon128v12_ref ssl crypto)

set_target_properties(test PROPERTIES
	XCODE_GENERATE_SCHEME ON
)
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT "test")

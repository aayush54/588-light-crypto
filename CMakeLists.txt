cmake_minimum_required(VERSION 3.20)

project(588-light-crypto)

add_executable(test src/test.cpp)
target_compile_features(test PRIVATE cxx_std_20)

add_subdirectory(ascon-c EXCLUDE_FROM_ALL)

target_link_libraries(test PUBLIC ${target} crypto_aead_ascon128v12_ref)

set_target_properties(test PROPERTIES
	XCODE_GENERATE_SCHEME ON
)
set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT "test")

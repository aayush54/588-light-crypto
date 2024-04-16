cmake_minimum_required(VERSION 3.16)

project(588-light-crypto)

if(MSVC)
	if(NOT CMAKE_GENERATOR STREQUAL "Ninja")
    	add_definitions(/MP)				# parallelize each target, unless Ninja is the generator
	endif()
endif()

## Find catkin and any catkin packages
find_package(OpenSSL REQUIRED)
find_package(catkin REQUIRED COMPONENTS roscpp rospy std_msgs image_transport cv_bridge roslaunch)
roslaunch_add_file_check(launch)
set(CRYPTO_LIB crypto_aead_ascon128v12_ref)

catkin_package()

include_directories(include ${catkin_INCLUDE_DIRS})

# add_executable(test_crypto src/crypto_helpers.cpp)
# target_compile_features(test_crypto PRIVATE cxx_std_20)

add_subdirectory(ascon-c EXCLUDE_FROM_ALL)

set(WITH_APPS OFF CACHE INTERNAL "")
# add_subdirectory(openssl-cmake EXCLUDE_FROM_ALL)

# target_link_libraries(test_crypto PUBLIC ${target} ${CRYPTO_LIB})

# set_target_properties(test_crypto PROPERTIES
# 	XCODE_GENERATE_SCHEME ON
# )
# set_property(DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR} PROPERTY VS_STARTUP_PROJECT "test_crypto")

## Build encrypt and decrypt nodes
add_executable(encrypt src/encrypt_teleop.cpp src/crypto_helpers.cpp)
target_compile_features(encrypt PRIVATE cxx_std_20)
target_link_libraries(encrypt ${catkin_LIBRARIES} crypto_aead_ascon128v12_ref OpenSSL::Crypto)
# add_dependencies(encrypt test_crypto)

add_executable(decrypt src/decrypt_teleop.cpp src/crypto_helpers.cpp)
target_compile_features(decrypt PRIVATE cxx_std_20)
target_link_libraries(decrypt ${catkin_LIBRARIES} crypto_aead_ascon128v12_ref OpenSSL::Crypto)
# add_dependencies(decrypt test_crypto)

add_executable(basic src/encrypt_test.cpp src/crypto_helpers.cpp)
target_compile_features(basic PRIVATE cxx_std_20)
target_link_libraries(basic ${catkin_LIBRARIES} crypto_aead_ascon128v12_ref OpenSSL::Crypto)
# message(FATAL_ERROR Libraries=${CRYPTO_LIB})
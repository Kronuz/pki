# pki: an offline certificate authority for a cluster's TLS, over OpenSSL 3.
#
#   cmake -B build -DCMAKE_BUILD_TYPE=Release && cmake --build build && ctest --test-dir build
#
# A static library (target pki::pki) holding the profile, the authority directory's
# checks, and the command entry point pki::run(), which each consumer's binary calls
# with its own consumer fixed (`xapiand pki ...`). kronuz-pki is the example and test
# driver, built only when this repository is top-level, and never packaged.

cmake_minimum_required(VERSION 3.16)
project(pki VERSION 0.1.0 LANGUAGES CXX)

include(FetchContent)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
if(NOT CMAKE_BUILD_TYPE)
	set(CMAKE_BUILD_TYPE Release)
endif()

# OpenSSL 3.0 is the floor, as for reactor::tls. LibreSSL is not OpenSSL 3.
find_package(OpenSSL 3.0 REQUIRED)
message(STATUS "pki: OpenSSL ${OPENSSL_VERSION} at ${OPENSSL_INCLUDE_DIR}")

# io: EINTR-safe calls and io::full_fsync. A consumer that compiles io.cc into its own
# objects (Xapiand, with its trace and fault seams) sets PKI_LINK_IO=OFF, so pki adds
# io's headers and no second copy of its symbols.
option(PKI_LINK_IO "Link io::io (OFF when the consumer compiles io.cc itself)" ON)
if(NOT TARGET io::io AND NOT DEFINED io_SOURCE_DIR)
	FetchContent_Declare(io GIT_REPOSITORY https://github.com/Kronuz/io.git GIT_TAG 1336f85d00616187c633d372548aab3e4b843426)
	FetchContent_MakeAvailable(io)
endif()

set(PKI_SOURCES
	src/command.cc
	src/directory.cc
	src/expiry.cc
	src/fingerprint.cc
	src/key.cc
	src/pem.cc
	src/refusal.cc
	src/secret.cc
)

# pki_add_library(NAME [TEST_HOOKS]): the release library, and the variant the tests
# link, which alone reads PKI_TEST_NOW (and later PKI_TEST_KILL_AT).
function(pki_add_library name)
	add_library(${name} STATIC ${PKI_SOURCES})
	target_include_directories(${name} PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/include")
	target_compile_features(${name} PUBLIC cxx_std_20)
	target_compile_definitions(${name} PRIVATE PKI_VERSION="${PROJECT_VERSION}")
	target_link_libraries(${name} PUBLIC OpenSSL::Crypto)
	if(PKI_LINK_IO)
		target_link_libraries(${name} PUBLIC io::io)
	else()
		target_include_directories(${name} PUBLIC "${io_SOURCE_DIR}")
	endif()
	if(ARGN STREQUAL "TEST_HOOKS")
		target_compile_definitions(${name} PRIVATE PKI_TEST_HOOKS=1)
	endif()
endfunction()

pki_add_library(pki)
add_library(pki::pki ALIAS pki)

# --- the driver, the tests (built only when this repo is top-level) ---
if(CMAKE_SOURCE_DIR STREQUAL CMAKE_CURRENT_SOURCE_DIR)
	enable_testing()

	add_executable(kronuz-pki examples/kronuz_pki.cc)
	target_link_libraries(kronuz-pki PRIVATE pki::pki)

	pki_add_library(pki_testing TEST_HOOKS)

	# The tests shell out to the openssl beside the linked library: macOS's
	# /usr/bin/openssl is LibreSSL.
	get_filename_component(PKI_OPENSSL_PREFIX "${OPENSSL_INCLUDE_DIR}" DIRECTORY)
	find_program(PKI_TEST_OPENSSL openssl HINTS "${PKI_OPENSSL_PREFIX}/bin" NO_DEFAULT_PATH)
	find_program(PKI_TEST_OPENSSL openssl REQUIRED)

	foreach(t files key fingerprint expiry command)
		add_executable(pki_${t}_test test/${t}_test.cc test/fixture.cc)
		target_link_libraries(pki_${t}_test PRIVATE pki_testing)
		target_compile_definitions(pki_${t}_test PRIVATE PKI_TEST_OPENSSL="${PKI_TEST_OPENSSL}")
		add_test(NAME pki_${t} COMMAND pki_${t}_test WORKING_DIRECTORY "${CMAKE_CURRENT_BINARY_DIR}")
		set_tests_properties(pki_${t} PROPERTIES TIMEOUT 120)
	endforeach()

	# The release driver carries no test hook.
	add_test(NAME pki_release_has_no_test_hooks
		COMMAND ${CMAKE_COMMAND} -DBINARY=$<TARGET_FILE:kronuz-pki> -P "${CMAKE_CURRENT_SOURCE_DIR}/cmake/no_test_hooks.cmake")
endif()

cmake_minimum_required(VERSION 3.16)

project(WPK
	VERSION 1.0.0
	DESCRIPTION "WPK archive library"
	LANGUAGES C CXX
)

option(LIBWPK_CLI "Build libwpk cli." ON)
option(LIBWPK_TESTS "Build libwpk tests." OFF)

include(GNUInstallDirs)

# Require standard C11 without compiler extensions.
set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)
set(CMAKE_C_EXTENSIONS OFF)

# Require standard C++17 without compiler extensions.
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# --------------------------------------------------
# Dependencies
# --------------------------------------------------

if(ANDROID)
	include(${CMAKE_CURRENT_SOURCE_DIR}/cmake/AndroidLibraryPackageManager.cmake)

	add_android_package(
		URL "https://github.com/MrR736/librarys-builds/releases/download/MbedTLS-4.2.0-build/MbedTLS-4.2.0-AndroidLibrary.tar.xz"
		SHA256 671deb6fbd9916b9b2a8002c8b5412ea2765dcf175c037d37acfd27b245ad5ef
	)

	find_android_package(MbedTLS VERSION 4.2.0 REQUIRED)
else()
	find_package(MbedTLS REQUIRED)
endif()

set(WPK_PLATFORM_LIBRARIES)

if(WIN32)
	set(WPK_PLATFORM_LIBRARIES ole32)
elseif(NOT ANDROID)
	find_library(UUID_LIBRARY NAMES uuid REQUIRED)
	set(WPK_PLATFORM_LIBRARIES ${UUID_LIBRARY})
endif()

# --------------------------------------------------
# WPK library
# --------------------------------------------------

add_library(wpk STATIC
	src/wpk.c
	src/wpk_compress.c
	src/wpk_crypto.c
	src/wpk_extract.c
	src/wpk_reader.c
	src/wpk_uuid.c
	src/miniz/miniz.c
)

target_include_directories(wpk
	PUBLIC
		${CMAKE_CURRENT_SOURCE_DIR}/include
		${CMAKE_CURRENT_SOURCE_DIR}/include/wpk
		${CMAKE_CURRENT_SOURCE_DIR}/include/wpk/miniz
	PRIVATE
		${CMAKE_CURRENT_SOURCE_DIR}/src
)

if(ANDROID)
	target_include_directories(wpk
		PRIVATE
			${CMAKE_CURRENT_SOURCE_DIR}/third-party/mbedtls/include
			${CMAKE_CURRENT_SOURCE_DIR}/third-party/mbedtls/tf-psa-crypto/include
			${CMAKE_CURRENT_SOURCE_DIR}/third-party/mbedtls/tf-psa-crypto/drivers/builtin/include
			${CMAKE_CURRENT_SOURCE_DIR}/third-party/mbedtls/tf-psa-crypto/drivers/builtin/include/mbedtls/private
	)
endif()

target_link_libraries(wpk
	PUBLIC
		MbedTLS::tfpsacrypto
		${WPK_PLATFORM_LIBRARIES}
)

target_compile_options(wpk PRIVATE -Wno-unused-function)

if(UNIX AND NOT APPLE)
	target_compile_definitions(wpk PRIVATE
		_FILE_OFFSET_BITS=64
		_POSIX_C_SOURCE=200809L
		_XOPEN_SOURCE=700
	)
endif()

if(MSVC)
	target_compile_options(wpk PRIVATE /W4)
else()
	target_compile_options(wpk PRIVATE -Wall -Wextra -Wpedantic)
endif()

target_compile_options(wpk PRIVATE
	$<$<CONFIG:Release>:-Os>
	-ffunction-sections
	-fdata-sections
	-fno-rtti
)

target_link_options(wpk PRIVATE
	$<$<CONFIG:Release>:-Wl,--gc-sections>
	$<$<CONFIG:Release>:-Wl,--strip-all>
)

install(TARGETS wpk
	RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
	LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
	ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

install(DIRECTORY ${CMAKE_SOURCE_DIR}/include/wpk
	DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}
#	FILES_MATCHING PATTERN "*.h"
)

if(LIBWPK_CLI)
	add_executable(wpkc cli/wpkc.cpp)
	target_include_directories(wpkc
		PRIVATE
			${CMAKE_CURRENT_SOURCE_DIR}/include
			${CMAKE_CURRENT_SOURCE_DIR}/src
	)

	target_link_libraries(wpkc PRIVATE wpk)

	add_executable(webinitg
		${CMAKE_CURRENT_SOURCE_DIR}/webinitg/src/cJSON/cJSON.c
		${CMAKE_CURRENT_SOURCE_DIR}/webinitg/src/cjsonconfig.c
		${CMAKE_CURRENT_SOURCE_DIR}/webinitg/src/javagenerate.c
		${CMAKE_CURRENT_SOURCE_DIR}/webinitg/src/main.c
		${CMAKE_CURRENT_SOURCE_DIR}/webinitg/src/runcjson.c
	)
	find_package(OpenSSL REQUIRED)

	target_link_libraries(webinitg PRIVATE OpenSSL::Crypto)

	target_include_directories(webinitg
		PRIVATE
			${CMAKE_CURRENT_SOURCE_DIR}/include
			${CMAKE_CURRENT_SOURCE_DIR}/src
	)

	target_compile_definitions(webinitg PRIVATE LIBXC_DISABLE_LOCALE)

	target_link_libraries(webinitg PRIVATE wpk)

	if(UNIX AND NOT APPLE)
		target_compile_definitions(webinitg PRIVATE
			_GNU_SOURCE
			_DEFAULT_SOURCE
			_POSIX_C_SOURCE=200809L
		)
	endif()

	install(TARGETS wpkc webinitg
		RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
		LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
		ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
	)
endif()

if(LIBWPK_TESTS)
	include(CTest)

	add_executable(wpktest test/wpktest.c)

	target_include_directories(wpktest
		PRIVATE
			${CMAKE_CURRENT_SOURCE_DIR}/include
			${CMAKE_CURRENT_SOURCE_DIR}/src
	)

	target_link_libraries(wpktest PRIVATE wpk)
	add_test(NAME wpk_tests COMMAND wpktest)
endif()
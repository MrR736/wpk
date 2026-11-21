# AndroidLibraryPackageManager.cmake
# Distributed under the OSI-approved BSD 3-Clause License.

cmake_minimum_required(VERSION 3.20)

set(
	ANDROID_LIBRARY_PACKAGE_MANAGER_VERSION
	"1.0.0"
	CACHE INTERNAL "Android Library Package Manager version"
)

# Home directory
if(DEFINED ENV{HOME} AND NOT "$ENV{HOME}" STREQUAL "")
	set(_ANDROID_LIBRARY_HOME "$ENV{HOME}")
elseif(DEFINED ENV{USERPROFILE} AND NOT "$ENV{USERPROFILE}" STREQUAL "")
	set(_ANDROID_LIBRARY_HOME "$ENV{USERPROFILE}")
else()
	message(FATAL_ERROR "Cannot determine home directory.")
endif()

# Android Libraries directory
set(
	ANDROID_LIBRARY_HOME
	"${_ANDROID_LIBRARY_HOME}/Android/Libraries"
	CACHE PATH "Android Library installation directory"
)

unset(_ANDROID_LIBRARY_HOME)

# Create directory
file(MAKE_DIRECTORY "${ANDROID_LIBRARY_HOME}")

# Set default Android package
function(_set_default_android_package _PACKAGE _VERSION)
	if("${_PACKAGE}" STREQUAL ""
		OR NOT "${_PACKAGE}" MATCHES "^[A-Za-z0-9_.+-]+$"
	)
		message(FATAL_ERROR
			"_set_default_android_package: Invalid package name '${_PACKAGE}'."
		)
	endif()

	if("${_VERSION}" STREQUAL ""
		OR NOT "${_VERSION}" MATCHES "^[A-Za-z0-9_.+-]+$"
		OR "${_VERSION}" STREQUAL "default"
	)
		message(FATAL_ERROR
			"_set_default_android_package: Invalid package version '${_VERSION}'."
		)
	endif()

	set(_PACKAGE_DIRECTORY
		"${ANDROID_LIBRARY_HOME}/${_PACKAGE}/${_VERSION}"
	)

	set(_DEFAULT_DIRECTORY
		"${ANDROID_LIBRARY_HOME}/${_PACKAGE}/default"
	)

	if(NOT EXISTS "${_PACKAGE_DIRECTORY}/AndroidLibrary.cmake")
		message(FATAL_ERROR
			"_set_default_android_package: Package version is not installed.\n"
			"${_PACKAGE_DIRECTORY}"
		)
	endif()

	# Remove previous default
	if(EXISTS "${_DEFAULT_DIRECTORY}" OR IS_SYMLINK "${_DEFAULT_DIRECTORY}")
		file(REMOVE_RECURSE "${_DEFAULT_DIRECTORY}")
	endif()

	# Link versioned package as default
	file(CREATE_LINK
		"${_PACKAGE_DIRECTORY}"
		"${_DEFAULT_DIRECTORY}"
		SYMBOLIC
	)

	if(NOT EXISTS "${_DEFAULT_DIRECTORY}/AndroidLibrary.cmake")
		message(FATAL_ERROR
			"_set_default_android_package: Failed to link default package.\n"
			"${_DEFAULT_DIRECTORY}"
		)
	endif()

	message(STATUS
		"Android Library Manager: "
		"Set ${_PACKAGE} ${_VERSION} as default."
	)
endfunction()

# Add Android package
function(_add_android_package)
	cmake_parse_arguments(
		PARSE_ARGV 0
		_ANDROID_PACKAGE
		"FORCE"
		"FILE;URL;SHA256"
		""
	)

	# Validate arguments
	if(_ANDROID_PACKAGE_URL AND _ANDROID_PACKAGE_FILE)
		message(FATAL_ERROR
			"add_android_packages: Specify either URL or FILE, not both."
		)
	endif()

	if(NOT _ANDROID_PACKAGE_URL AND NOT _ANDROID_PACKAGE_FILE)
		message(FATAL_ERROR
			"add_android_packages: Either URL or FILE is required."
		)
	endif()

	if(_ANDROID_PACKAGE_SHA256)
		string(LENGTH "${_ANDROID_PACKAGE_SHA256}" _SHA256_LENGTH)

		if(NOT _SHA256_LENGTH EQUAL 64
			OR NOT "${_ANDROID_PACKAGE_SHA256}" MATCHES "^[a-fA-F0-9]+$")
			message(FATAL_ERROR
				"add_android_packages: Invalid SHA256 checksum."
			)
		endif()
	endif()

	if(_ANDROID_PACKAGE_UNPARSED_ARGUMENTS)
		message(FATAL_ERROR
			"add_android_packages: Unknown arguments: "
			"${_ANDROID_PACKAGE_UNPARSED_ARGUMENTS}"
		)
	endif()

	# Package name and version are read from AndroidLibrary.json.
	# They are not known until the archive has been extracted.

	# Prepare temporary directories
	set(_DOWNLOAD_DIRECTORY
		"${ANDROID_LIBRARY_HOME}/.downloads"
	)

	set(_ARCHIVE
		"${_DOWNLOAD_DIRECTORY}/AndroidLibrary.tar.xz"
	)

	set(_EXTRACT_DIRECTORY
		"${_DOWNLOAD_DIRECTORY}/AndroidLibrary"
	)

	file(MAKE_DIRECTORY "${_DOWNLOAD_DIRECTORY}")

	# Clean previous temporary files
	file(REMOVE "${_ARCHIVE}")
	file(REMOVE_RECURSE "${_EXTRACT_DIRECTORY}")

	# Obtain package archive
	if(_ANDROID_PACKAGE_FILE)

		get_filename_component(
			_PACKAGE_SOURCE
			"${_ANDROID_PACKAGE_FILE}"
			ABSOLUTE
			BASE_DIR "${CMAKE_CURRENT_SOURCE_DIR}"
		)

		if(NOT EXISTS "${_PACKAGE_SOURCE}"
			OR IS_DIRECTORY "${_PACKAGE_SOURCE}")
			message(FATAL_ERROR
				"add_android_packages: Invalid archive file:\n"
				"${_PACKAGE_SOURCE}"
			)
		endif()

		message(STATUS
			"Android Library Manager: "
			"Using local archive ${_PACKAGE_SOURCE}"
		)

		configure_file(
			"${_PACKAGE_SOURCE}"
			"${_ARCHIVE}"
			COPYONLY
		)

	else()

		message(STATUS
			"Android Library Manager: "
			"Downloading Android library package..."
		)

		file(DOWNLOAD
			"${_ANDROID_PACKAGE_URL}"
			"${_ARCHIVE}"
			SHOW_PROGRESS
			TLS_VERIFY ON
			STATUS _DOWNLOAD_STATUS
			LOG _DOWNLOAD_LOG
		)

		list(GET _DOWNLOAD_STATUS 0 _DOWNLOAD_CODE)
		list(GET _DOWNLOAD_STATUS 1 _DOWNLOAD_MESSAGE)

		if(NOT _DOWNLOAD_CODE EQUAL 0)
			file(REMOVE "${_ARCHIVE}")

			message(FATAL_ERROR
				"Android Library Manager: Download failed.\n"
				"Package: ${_PACKAGE}\n"
				"Reason: ${_DOWNLOAD_MESSAGE}\n"
				"${_DOWNLOAD_LOG}"
			)
		endif()

	endif()

	# Verify archive checksum
	if(_ANDROID_PACKAGE_SHA256)

		file(SHA256 "${_ARCHIVE}" _ARCHIVE_SHA256)

		string(TOLOWER
			"${_ARCHIVE_SHA256}"
			_ARCHIVE_SHA256
		)

		string(TOLOWER
			"${_ANDROID_PACKAGE_SHA256}"
			_EXPECTED_SHA256
		)

		if(NOT "${_ARCHIVE_SHA256}" STREQUAL "${_EXPECTED_SHA256}")
			file(REMOVE "${_ARCHIVE}")

			message(FATAL_ERROR
				"Android Library Manager: SHA256 mismatch.\n"
				"Expected: ${_EXPECTED_SHA256}\n"
				"Actual: ${_ARCHIVE_SHA256}"
			)
		endif()

	endif()

	# Extract archive
	message(STATUS
		"Android Library Manager: "
		"Extracting Android library package..."
	)

	file(ARCHIVE_EXTRACT
		INPUT "${_ARCHIVE}"
		DESTINATION "${_EXTRACT_DIRECTORY}"
	)

	# Validate extracted package
	if(NOT EXISTS "${_EXTRACT_DIRECTORY}/AndroidLibrary.cmake"
		OR NOT EXISTS "${_EXTRACT_DIRECTORY}/AndroidLibrary.json")

		file(REMOVE "${_ARCHIVE}")
		file(REMOVE_RECURSE "${_EXTRACT_DIRECTORY}")

		message(FATAL_ERROR
			"Android Library Manager: Invalid package archive.\n"
			"Required files were not found:\n"
			"  AndroidLibrary.cmake\n"
			"  AndroidLibrary.json"
		)
	endif()

	# Read package metadata
	set(_PACKAGE_JSON
		"${_EXTRACT_DIRECTORY}/AndroidLibrary.json"
	)

	file(READ "${_PACKAGE_JSON}" _PACKAGE_JSON_CONTENT)

	# Read and validate project name.
	string(JSON _JSON_TYPE
		ERROR_VARIABLE _JSON_ERROR
		TYPE "${_PACKAGE_JSON_CONTENT}"
		project
	)

	if(NOT "${_JSON_ERROR}" STREQUAL "NOTFOUND"
		OR NOT "${_JSON_TYPE}" STREQUAL "STRING")

		file(REMOVE "${_ARCHIVE}")
		file(REMOVE_RECURSE "${_EXTRACT_DIRECTORY}")

		message(FATAL_ERROR
			"Android Library Manager: Invalid AndroidLibrary.json.\n"
			"Expected a string property named 'project'."
		)
	endif()

	string(JSON _PACKAGE
		ERROR_VARIABLE _JSON_ERROR
		GET "${_PACKAGE_JSON_CONTENT}"
		project
	)

	if(NOT "${_JSON_ERROR}" STREQUAL "NOTFOUND"
		OR "${_PACKAGE}" STREQUAL ""
		OR NOT "${_PACKAGE}" MATCHES "^[A-Za-z0-9_.+-]+$")

		file(REMOVE "${_ARCHIVE}")
		file(REMOVE_RECURSE "${_EXTRACT_DIRECTORY}")

		message(FATAL_ERROR
			"Android Library Manager: Invalid project name "
			"in AndroidLibrary.json."
		)
	endif()

	string(JSON _JSON_TYPE
		ERROR_VARIABLE _JSON_ERROR
		TYPE "${_PACKAGE_JSON_CONTENT}"
		project_version
	)

	if(NOT "${_JSON_ERROR}" STREQUAL "NOTFOUND"
		OR NOT "${_JSON_TYPE}" STREQUAL "STRING")

		file(REMOVE "${_ARCHIVE}")
		file(REMOVE_RECURSE "${_EXTRACT_DIRECTORY}")

		message(FATAL_ERROR
			"Android Library Manager: Invalid AndroidLibrary.json.\n"
			"Expected a string property named 'project_version'."
		)
	endif()

	string(JSON _PACKAGE_METADATA_VERSION
		ERROR_VARIABLE _JSON_ERROR
		GET "${_PACKAGE_JSON_CONTENT}"
		project_version
	)

	if(NOT "${_JSON_ERROR}" STREQUAL "NOTFOUND"
		OR "${_PACKAGE_METADATA_VERSION}" STREQUAL ""
		OR NOT "${_PACKAGE_METADATA_VERSION}" MATCHES "^[A-Za-z0-9_.+-]+$")

		file(REMOVE "${_ARCHIVE}")
		file(REMOVE_RECURSE "${_EXTRACT_DIRECTORY}")

		message(FATAL_ERROR
			"Android Library Manager: Invalid project_version "
			"in AndroidLibrary.json."
		)
	endif()

	# Use the version declared by the package metadata.
	set(_INSTALL_VERSION "${_PACKAGE_METADATA_VERSION}")

	# Determine installation directory from package metadata.
	set(_PACKAGE_DIRECTORY
		"${ANDROID_LIBRARY_HOME}/${_PACKAGE}/${_INSTALL_VERSION}"
	)

	# Check existing installation after reading package metadata.
	if(EXISTS "${_PACKAGE_DIRECTORY}/AndroidLibrary.cmake"
		AND NOT _ANDROID_PACKAGE_FORCE)

		file(REMOVE "${_ARCHIVE}")
		file(REMOVE_RECURSE "${_EXTRACT_DIRECTORY}")

		message(STATUS
			"Android Library Manager: "
			"${_PACKAGE} ${_INSTALL_VERSION} is already installed."
		)

		_set_default_android_package(
			"${_PACKAGE}"
			"${_INSTALL_VERSION}"
		)

		return()
	endif()

	# Prepare installation destination
	get_filename_component(
		_PACKAGE_PARENT
		"${_PACKAGE_DIRECTORY}"
		DIRECTORY
	)

	file(MAKE_DIRECTORY "${_PACKAGE_PARENT}")

	# Preserve previous installation until replacement is ready
	set(_BACKUP_DIRECTORY
		"${_PACKAGE_DIRECTORY}.backup"
	)

	file(REMOVE_RECURSE "${_BACKUP_DIRECTORY}")

	set(_HAD_PREVIOUS_INSTALLATION FALSE)

	if(EXISTS "${_PACKAGE_DIRECTORY}"
		OR IS_SYMLINK "${_PACKAGE_DIRECTORY}")

		execute_process(
			COMMAND "${CMAKE_COMMAND}" -E rename
				"${_PACKAGE_DIRECTORY}"
				"${_BACKUP_DIRECTORY}"
			RESULT_VARIABLE _BACKUP_RESULT
			ERROR_VARIABLE _BACKUP_ERROR
		)

		if(NOT "${_BACKUP_RESULT}" STREQUAL "0")
			file(REMOVE "${_ARCHIVE}")
			file(REMOVE_RECURSE "${_EXTRACT_DIRECTORY}")

			message(FATAL_ERROR
				"Android Library Manager: Failed to back up "
				"existing installation.\n"
				"${_BACKUP_ERROR}"
			)
		endif()

		set(_HAD_PREVIOUS_INSTALLATION TRUE)
	endif()

	# Install package
	execute_process(
		COMMAND "${CMAKE_COMMAND}" -E rename
			"${_EXTRACT_DIRECTORY}"
			"${_PACKAGE_DIRECTORY}"
		RESULT_VARIABLE _INSTALL_RESULT
		ERROR_VARIABLE _INSTALL_ERROR
	)

	if(NOT "${_INSTALL_RESULT}" STREQUAL "0")

		# Restore previous installation
		if(_HAD_PREVIOUS_INSTALLATION)
			execute_process(
				COMMAND "${CMAKE_COMMAND}" -E rename
					"${_BACKUP_DIRECTORY}"
					"${_PACKAGE_DIRECTORY}"
				RESULT_VARIABLE _RESTORE_RESULT
				ERROR_VARIABLE _RESTORE_ERROR
			)
		endif()

		file(REMOVE "${_ARCHIVE}")
		file(REMOVE_RECURSE "${_EXTRACT_DIRECTORY}")

		message(FATAL_ERROR
			"Android Library Manager: Installation failed.\n"
			"Package: ${_PACKAGE}\n"
			"Version: ${_PACKAGE_METADATA_VERSION}\n"
			"Destination: ${_PACKAGE_DIRECTORY}\n"
			"Reason: ${_INSTALL_ERROR}"
			"$<$<BOOL:${_HAD_PREVIOUS_INSTALLATION}>:\n"
			"Restore result: ${_RESTORE_RESULT}\n"
			"${_RESTORE_ERROR}>"
		)
	endif()

	# Verify installed package
	if(NOT EXISTS "${_PACKAGE_DIRECTORY}/AndroidLibrary.cmake"
		OR NOT EXISTS "${_PACKAGE_DIRECTORY}/AndroidLibrary.json")

		file(REMOVE_RECURSE "${_PACKAGE_DIRECTORY}")

		if(_HAD_PREVIOUS_INSTALLATION)
			execute_process(
				COMMAND "${CMAKE_COMMAND}" -E rename
					"${_BACKUP_DIRECTORY}"
					"${_PACKAGE_DIRECTORY}"
			)
		endif()

		file(REMOVE "${_ARCHIVE}")

		message(FATAL_ERROR
			"Android Library Manager: Installation verification failed.\n"
			"Package: ${_PACKAGE}\n"
			"Destination: ${_PACKAGE_DIRECTORY}"
		)
	endif()

	# Remove previous installation backup
	if(_HAD_PREVIOUS_INSTALLATION)
		file(REMOVE_RECURSE "${_BACKUP_DIRECTORY}")
	endif()

	# Update default package
	_set_default_android_package(
		"${_PACKAGE}"
		"${_PACKAGE_METADATA_VERSION}"
	)

	# Cleanup
	file(REMOVE "${_ARCHIVE}")

	message(STATUS
		"Android Library Manager: "
		"Installed ${_PACKAGE} ${_PACKAGE_METADATA_VERSION}."
	)

endfunction()


# Add multiple Android packages.
#
# URL and SHA256 values are paired by their order:
#   URL url1 SHA256 hash1 URL url2 SHA256 hash2
#
# FILE can be used instead of URL. Do not mix FILE and URL in one call.
function(add_android_packages)
	cmake_parse_arguments(
		PARSE_ARGV 0
		_ANDROID_PACKAGES
		"FORCE"
		""
		"URL;FILE;SHA256"
	)

	if(_ANDROID_PACKAGES_UNPARSED_ARGUMENTS)
		message(FATAL_ERROR
			"add_android_packages: Unknown arguments: "
			"${_ANDROID_PACKAGES_UNPARSED_ARGUMENTS}"
		)
	endif()

	if(_ANDROID_PACKAGES_URL AND _ANDROID_PACKAGES_FILE)
		message(FATAL_ERROR
			"add_android_packages: Do not mix URL and FILE arguments."
		)
	endif()

	if(NOT _ANDROID_PACKAGES_URL AND NOT _ANDROID_PACKAGES_FILE)
		message(FATAL_ERROR
			"add_android_packages: At least one URL or FILE is required."
		)
	endif()

	if(_ANDROID_PACKAGES_URL)
		set(_PACKAGE_SOURCES ${_ANDROID_PACKAGES_URL})
	else()
		set(_PACKAGE_SOURCES ${_ANDROID_PACKAGES_FILE})
	endif()

	list(LENGTH _PACKAGE_SOURCES _PACKAGE_COUNT)
	list(LENGTH _ANDROID_PACKAGES_SHA256 _SHA256_COUNT)

	if(_SHA256_COUNT GREATER 0
		AND NOT _SHA256_COUNT EQUAL _PACKAGE_COUNT)
		message(FATAL_ERROR
			"add_android_packages: Provide either no SHA256 values "
			"or exactly one SHA256 per package."
		)
	endif()

	if(_ANDROID_PACKAGES_URL)
		set(_SOURCE_ARGUMENT URL)
	else()
		set(_SOURCE_ARGUMENT FILE)
	endif()

	math(EXPR _LAST_INDEX "${_PACKAGE_COUNT} - 1")

	foreach(_INDEX RANGE ${_LAST_INDEX})
		list(GET _PACKAGE_SOURCES ${_INDEX} _PACKAGE_SOURCE)

		set(_PACKAGE_ARGUMENTS
			"${_SOURCE_ARGUMENT}" "${_PACKAGE_SOURCE}"
		)

		if(_SHA256_COUNT GREATER 0)
			list(GET _ANDROID_PACKAGES_SHA256 ${_INDEX} _PACKAGE_SHA256)
			list(APPEND _PACKAGE_ARGUMENTS SHA256 "${_PACKAGE_SHA256}")
		endif()

		if(_ANDROID_PACKAGES_FORCE)
			list(APPEND _PACKAGE_ARGUMENTS FORCE)
		endif()

		_add_android_package(${_PACKAGE_ARGUMENTS})
	endforeach()
endfunction()

# Find Android package
macro(find_android_package _PACKAGE)
	cmake_parse_arguments(
		_ANDROID_PACKAGE
		"REQUIRED"
		"VERSION"
		""
		${ARGN}
	)

	if(_ANDROID_PACKAGE_UNPARSED_ARGUMENTS)
		message(FATAL_ERROR
			"find_android_package: Unknown arguments: "
			"${_ALPM_FIND_UNPARSED_ARGUMENTS}"
		)
	endif()

	# Validate package name
	if("${_PACKAGE}" STREQUAL ""
		OR NOT "${_PACKAGE}" MATCHES "^[A-Za-z0-9_.+-]+$"
	)
		message(FATAL_ERROR
			"find_android_package: Invalid package name '${_PACKAGE}'."
		)
	endif()

	# Validate package version
	if(_ANDROID_PACKAGE_VERSION)
		if(NOT "${_ANDROID_PACKAGE_VERSION}" MATCHES "^[A-Za-z0-9_.+-]+$")
			message(FATAL_ERROR
				"find_android_package: Invalid package version "
				"'${_ANDROID_PACKAGE_VERSION}'."
			)
		endif()
	endif()

	# Validate unknown arguments
	if(_ANDROID_PACKAGE_UNPARSED_ARGUMENTS)
		message(FATAL_ERROR
			"find_android_package: Unknown arguments: "
			"${_ANDROID_PACKAGE_UNPARSED_ARGUMENTS}"
		)
	endif()

	# Validate Android Library home
	if(NOT DEFINED ANDROID_LIBRARY_HOME
		OR "${ANDROID_LIBRARY_HOME}" STREQUAL ""
	)
		message(FATAL_ERROR
			"find_android_package: ANDROID_LIBRARY_HOME is not configured."
		)
	endif()

	# Package directory
	set(_ANDROID_PACKAGE_DIRECTORY
		"${ANDROID_LIBRARY_HOME}/${_PACKAGE}"
	)

	# Package version
	if(_ANDROID_PACKAGE_VERSION)
		set(_ANDROID_PACKAGE_SELECTED_VERSION
			"${_ANDROID_PACKAGE_VERSION}"
		)
	else()
		set(_ANDROID_PACKAGE_SELECTED_VERSION "default")
	endif()

	# Package configuration
	set(_ANDROID_PACKAGE_CONFIG
		"${_ANDROID_PACKAGE_DIRECTORY}/${_ANDROID_PACKAGE_SELECTED_VERSION}/AndroidLibrary.cmake"
	)

	# Include package
	if(EXISTS "${_ANDROID_PACKAGE_CONFIG}")
		message(STATUS
			"Android Library Manager: "
			"Found ${_PACKAGE} ${_ANDROID_PACKAGE_SELECTED_VERSION}"
		)

		include("${_ANDROID_PACKAGE_CONFIG}")

	else()
		if(_ANDROID_PACKAGE_REQUIRED)
			message(FATAL_ERROR
				"Android Library Manager: "
				"Package '${_PACKAGE}' was not found.\n"
				"Version: ${_ANDROID_PACKAGE_SELECTED_VERSION}\n"
				"Expected: ${_ANDROID_PACKAGE_CONFIG}"
			)
		else()
			message(STATUS
				"Android Library Manager: "
				"Package '${_PACKAGE} ${_ANDROID_PACKAGE_SELECTED_VERSION}' "
				"was not found."
			)
		endif()
	endif()

	# Cleanup internal variables
	unset(_ANDROID_PACKAGE_DIRECTORY)
	unset(_ANDROID_PACKAGE_SELECTED_VERSION)
	unset(_ANDROID_PACKAGE_CONFIG)
	unset(_ANDROID_PACKAGE_VERSION)
	unset(_ANDROID_PACKAGE_REQUIRED)
	unset(_ANDROID_PACKAGE_UNPARSED_ARGUMENTS)
	unset(_ANDROID_PACKAGE_KEYWORDS_MISSING_VALUES)
endmacro()

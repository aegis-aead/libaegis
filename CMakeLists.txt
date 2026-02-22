cmake_minimum_required(VERSION 3.10)
project(aegis LANGUAGES C VERSION 0.9.1)

include(CMakePackageConfigHelpers)
include(GNUInstallDirs)

if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_C_STANDARD 99)

include_directories("src/include")

option(FAVOR_PERFORMANCE "Favor performance over side-channel mitigations" OFF)

if(FAVOR_PERFORMANCE)
  add_definitions(-DFAVOR_PERFORMANCE)
endif()

file(GLOB SOURCE_FILES "src/aegis128l/*.c" "src/aegis128x2/*.c" "src/aegis128x4/*.c" "src/aegis256/*.c" "src/aegis256x2/*.c" "src/aegis256x4/*.c" "src/common/*.c" "src/raf/*.c")
file(GLOB HEADER_FILES "src/include/*.h")

add_library("${PROJECT_NAME}")
add_library("${PROJECT_NAME}::${PROJECT_NAME}" ALIAS "${PROJECT_NAME}")

if(BUILD_SHARED_LIBS)
  set_target_properties("${PROJECT_NAME}" PROPERTIES VERSION "${PROJECT_VERSION}" SOVERSION 0)
endif()

target_sources("${PROJECT_NAME}" PRIVATE ${SOURCE_FILES})

target_include_directories("${PROJECT_NAME}"
                           PUBLIC $<BUILD_INTERFACE:${PROJECT_SOURCE_DIR}>
                                  $<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>)

# Installation

set(TARGETS_EXPORT_NAME "${PROJECT_NAME}-targets")

install(TARGETS "${PROJECT_NAME}"
        EXPORT "${TARGETS_EXPORT_NAME}"
        LIBRARY DESTINATION "${CMAKE_INSTALL_LIBDIR}"
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")

install(FILES ${HEADER_FILES} DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}")

# CMake find_package() support

set(INSTALL_CONFIG_DIR "${CMAKE_INSTALL_DATADIR}/cmake/${PROJECT_NAME}")

set(TARGETS_EXPORT_FILE_NAME "${TARGETS_EXPORT_NAME}.cmake")
set(TARGETS_EXPORT_FILE "${PROJECT_BINARY_DIR}/${TARGETS_EXPORT_FILE_NAME}")

install(EXPORT "${TARGETS_EXPORT_NAME}"
        FILE "${TARGETS_EXPORT_FILE_NAME}"
        NAMESPACE "${PROJECT_NAME}::"
        DESTINATION "${INSTALL_CONFIG_DIR}")

set(CONFIG_FILE_NAME "${PROJECT_NAME}-config.cmake")
set(CONFIG_TEMPLATE_FILE "${PROJECT_SOURCE_DIR}/cmake/${CONFIG_FILE_NAME}.in")
set(CONFIG_FILE "${PROJECT_BINARY_DIR}/${CONFIG_FILE_NAME}")

configure_package_config_file("${CONFIG_TEMPLATE_FILE}" "${CONFIG_FILE}"
                              INSTALL_DESTINATION "${INSTALL_CONFIG_DIR}")

install(FILES "${CONFIG_FILE}" DESTINATION "${INSTALL_CONFIG_DIR}")

write_basic_package_version_file("${PROJECT_NAME}-config-version.cmake" VERSION ${PROJECT_VERSION} COMPATIBILITY AnyNewerVersion)
install(FILES "${PROJECT_BINARY_DIR}/${PROJECT_NAME}-config-version.cmake" DESTINATION "${INSTALL_CONFIG_DIR}")

export(EXPORT "${TARGETS_EXPORT_NAME}" FILE "${TARGETS_EXPORT_FILE}" NAMESPACE "${PROJECT_NAME}::")

export(PACKAGE "${PROJECT_NAME}")

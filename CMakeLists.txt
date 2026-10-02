cmake_minimum_required(VERSION 3.16)
project(LinSFT VERSION 1.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)
if(NOT CMAKE_BUILD_TYPE)
  set(CMAKE_BUILD_TYPE Release)
endif()

if(NOT CMAKE_SYSTEM_NAME STREQUAL "Linux")
  message(FATAL_ERROR "LinSFT targets Linux only (Ubuntu / WSL2).")
endif()

add_compile_options(-Wall -Wextra -Wpedantic -Wshadow -fstack-protector-strong)
if(CMAKE_BUILD_TYPE STREQUAL "Release")
  add_compile_options(-O2 -D_FORTIFY_SOURCE=2)
endif()

find_package(Threads REQUIRED)
find_package(SQLite3 REQUIRED)

option(LINSFT_BUILD_GUI "Build the Qt6 GUI client (skipped automatically if Qt6 is missing)" ON)
option(LINSFT_BUILD_TESTS "Build the test-suite" ON)

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}/bin)

# Embed database/schema.sql into the server binary.
file(READ ${CMAKE_SOURCE_DIR}/database/schema.sql LINSFT_SCHEMA_SQL)
configure_file(${CMAKE_SOURCE_DIR}/cmake/schema_embedded.h.in
               ${CMAKE_BINARY_DIR}/generated/schema_embedded.h @ONLY)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${CMAKE_SOURCE_DIR}/database/schema.sql)

# ---- libraries -------------------------------------------------------------
add_library(linsft_common STATIC
  common/src/crypto.cpp common/src/protocol.cpp common/src/pathutil.cpp
  common/src/permissions.cpp common/src/models.cpp common/src/user.cpp)
target_include_directories(linsft_common PUBLIC common/include)

add_library(linsft_server_lib STATIC
  server/src/database.cpp server/src/logger.cpp server/src/auth.cpp server/src/file_manager.cpp
  server/src/transfer_manager.cpp server/src/system_monitor.cpp server/src/connection_handler.cpp
  server/src/server.cpp)
target_include_directories(linsft_server_lib PUBLIC server/include ${CMAKE_BINARY_DIR}/generated)
target_link_libraries(linsft_server_lib PUBLIC linsft_common SQLite::SQLite3 Threads::Threads)

add_library(linsft_client_lib STATIC client/src/client.cpp)
target_include_directories(linsft_client_lib PUBLIC client/include)
target_link_libraries(linsft_client_lib PUBLIC linsft_common Threads::Threads)

# ---- executables (also symlinked into the project root for convenience) ----
function(linsft_root_link target)
  # ./<target> plus optional extra alias names (e.g. file_server) as symlinks in the project root
  add_custom_command(TARGET ${target} POST_BUILD
    COMMAND ${CMAKE_COMMAND} -E create_symlink $<TARGET_FILE:${target}> ${CMAKE_SOURCE_DIR}/$<TARGET_FILE_NAME:${target}>
    COMMENT "Linking ./${target}")
  foreach(alias ${ARGN})
    add_custom_command(TARGET ${target} POST_BUILD
      COMMAND ${CMAKE_COMMAND} -E create_symlink $<TARGET_FILE:${target}> ${CMAKE_SOURCE_DIR}/${alias}
      COMMENT "Linking ./${alias}")
  endforeach()
endfunction()

add_executable(network-file-server server/src/main.cpp)
target_link_libraries(network-file-server PRIVATE linsft_server_lib)
linsft_root_link(network-file-server file_server)

add_executable(network-file-client client/src/cli_main.cpp)
target_link_libraries(network-file-client PRIVATE linsft_client_lib)
linsft_root_link(network-file-client file_client)

# ---- Qt6 GUI ---------------------------------------------------------------
set(LINSFT_GUI_ENABLED OFF)
if(LINSFT_BUILD_GUI)
  find_package(Qt6 COMPONENTS Widgets QUIET)
  if(Qt6_FOUND)
    set(CMAKE_AUTOMOC ON)
    add_library(linsft_gui_lib STATIC client/src/gui/main_window.cpp client/src/gui/login_dialog.cpp)
    target_include_directories(linsft_gui_lib PUBLIC client/src/gui)
    target_link_libraries(linsft_gui_lib PUBLIC linsft_client_lib Qt6::Widgets)
    add_executable(network-file-gui client/src/gui/gui_main.cpp)
    target_link_libraries(network-file-gui PRIVATE linsft_gui_lib)
    linsft_root_link(network-file-gui)
    set(LINSFT_GUI_ENABLED ON)
  else()
    message(WARNING "Qt6 Widgets not found - GUI skipped. Install: sudo apt install qt6-base-dev (CLI client still builds).")
  endif()
endif()

# ---- tests -----------------------------------------------------------------
if(LINSFT_BUILD_TESTS)
  enable_testing()
  add_subdirectory(tests)
endif()

message(STATUS "LinSFT ${PROJECT_VERSION}: GUI=${LINSFT_GUI_ENABLED} tests=${LINSFT_BUILD_TESTS}")

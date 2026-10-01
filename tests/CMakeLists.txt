function(linsft_test name)
  add_executable(${name} ${ARGN})
  target_link_libraries(${name} PRIVATE linsft_server_lib linsft_client_lib)
  target_include_directories(${name} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME ${name} COMMAND ${name})
  set_tests_properties(${name} PROPERTIES TIMEOUT 240)
endfunction()

linsft_test(test_unit test_unit.cpp)
linsft_test(test_integration test_integration.cpp)

# End-to-end test of the real binaries (server process, CLI client, SIGINT shutdown).
add_test(NAME test_e2e_cli
  COMMAND ${CMAKE_CURRENT_SOURCE_DIR}/e2e_cli.sh $<TARGET_FILE:network-file-server> $<TARGET_FILE:network-file-client>)
set_tests_properties(test_e2e_cli PROPERTIES TIMEOUT 120)
add_dependencies(test_integration network-file-server network-file-client)


if(LINSFT_GUI_ENABLED)
  add_executable(test_gui test_gui.cpp)
  target_link_libraries(test_gui PRIVATE linsft_gui_lib linsft_server_lib Qt6::Widgets)
  target_include_directories(test_gui PRIVATE ${CMAKE_CURRENT_SOURCE_DIR})
  add_test(NAME test_gui COMMAND test_gui)
  set_tests_properties(test_gui PROPERTIES TIMEOUT 120 ENVIRONMENT "QT_QPA_PLATFORM=offscreen")
endif()

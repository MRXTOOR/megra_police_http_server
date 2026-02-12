cmake_minimum_required(VERSION 3.10)

project(megra_police_http_server CXX)

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_executable(megra_police_http_server
  src/main.cpp
)

if(UNIX)
  enable_testing()

  add_test(
    NAME server_integration_test
    COMMAND bash "${CMAKE_SOURCE_DIR}/tests/test_server.sh" $<TARGET_FILE:megra_police_http_server>
  )
endif()


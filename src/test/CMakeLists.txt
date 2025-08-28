set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/test")

add_executable(test test.cpp)
target_link_libraries(test PRIVATE ${PROJECT_NAME})

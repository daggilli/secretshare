set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/commandline")

add_executable(share share.cpp)
target_link_libraries(share PRIVATE ${PROJECT_NAME})

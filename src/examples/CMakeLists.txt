set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/examples/$<CONFIG>")

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_RELEASE ON)

add_executable(membuffer membuffer.cpp)

target_compile_options(membuffer PRIVATE
  $<$<CONFIG:Debug>:-g -O1 -fno-omit-frame-pointer>
  $<$<CONFIG:Release>: -O4 -DNODEBUG -ffunction-sections -fdata-sections -fno-plt>
  $<$<AND:$<CONFIG:Debug>,$<BOOL:${ENABLE_ASAN}>>:-fsanitize=address>
)

target_link_options(membuffer PRIVATE
  $<$<CONFIG:Release>: -Wl,--gc-sections -Wl,--as-needed>
  $<$<AND:$<CONFIG:Debug>,$<BOOL:${ENABLE_ASAN}>>:-fsanitize=address>
)

target_link_libraries(membuffer PRIVATE ${PROJECT_NAME})

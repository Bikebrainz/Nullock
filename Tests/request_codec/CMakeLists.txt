add_executable(request_codec_test request_codec_test.cpp)
target_link_libraries(request_codec_test PRIVATE Networking Qt6::Core Qt6::Network)
target_include_directories(request_codec_test PRIVATE ${CMAKE_SOURCE_DIR}/Src/Core/Networking)
add_test(NAME request_codec COMMAND request_codec_test)

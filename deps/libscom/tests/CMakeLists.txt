include_directories()

# build tgw_crypto .so/.a
set(SOURCE_FILES uuid_test.cpp)
add_executable(uuid_test ${SOURCE_FILES})
if(UNIX)
    target_link_libraries(uuid_test)
else()
    target_link_libraries(tgw_crypto)
endif()
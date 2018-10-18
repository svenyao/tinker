include_directories()

if(UNIX)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libstdc++ -static-libgcc -fPIC")
else()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWIN32_LEAN_AND_MEAN 
        -D_CRT_SECURE_NO_WARNINGS -DTGW_CRYPTO_EXPORTS")
endif()

# build tgw_crypto .so/.a
set(SOURCE_FILES tgw_crypto.cpp hardware_util.cpp tgw_crypto.h)
add_library(tgw_crypto SHARED ${SOURCE_FILES})
if(UNIX)
target_link_libraries(tgw_crypto crypto.a dl)
else()
target_link_libraries(tgw_crypto wsock32 ws2_32 Crypt32 libcrypto-static)
set_target_properties(tgw_crypto PROPERTIES COMPILE_FLAGS "/wd4251 /wd4819 /wd4996 /wd4273 /wd4275")
endif()

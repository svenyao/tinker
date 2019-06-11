include_directories()

if(UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -static-libstdc++ -static-libgcc -fPIC")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWIN32_LEAN_AND_MEAN
        -D_CRT_SECURE_NO_WARNINGS")
endif()

# build tgw_crypto .so/.a
set(SOURCE_FILES fgs_crypto.h fgs_crypto.cpp hardware_util.cpp crypto.h crypto.cpp)
add_library(fgs_crypto ${SOURCE_FILES})
if(UNIX)
    target_link_libraries(fgs_crypto crypto.a dl)
else()
    target_link_libraries(fgs_crypto wsock32 ws2_32 Crypt32 libcrypto-static)
    set_target_properties(fgs_crypto PROPERTIES COMPILE_FLAGS "/wd4251 /wd4819 /wd4996 /wd4273 /wd4275")
    SET_TARGET_PROPERTIES(fgs_crypto PROPERTIES OUTPUT_NAME "fgs_crypto-static")
endif()

if (UNIX)
    add_library(fgs_crypto_so SHARED ${SOURCE_FILES})
    target_link_libraries(fgs_crypto_so crypto.a dl)
    SET_TARGET_PROPERTIES(fgs_crypto_so PROPERTIES OUTPUT_NAME "fgs_crypto")
endif()

include_directories(../include)

if(UNIX)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11 -static-libstdc++ -static-libgcc -fPIC")
else()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS -DTINKER_EXPORTS")
endif()

# build tinker_crypto .so/.a
set(HEADER_FILES ../include/crypto.h ../include/hardware.h)
set(SOURCE_FILES crypto.cpp hardware.cpp)
# tinker_crypto.so
add_library(tinker_crypto SHARED ${SOURCE_FILES} ${HEADER_FILES})
if(UNIX)
target_link_libraries(tinker_crypto ssl crypto)
else()
target_link_libraries(tinker_crypto wsock32 ws2_32 Crypt32 libssl-static 
		libcrypto-static)
set_target_properties(tinker_crypto PROPERTIES COMPILE_FLAGS "/wd4251 /wd4819 /wd4275")
endif()

# tinker_crypto.a
if(UNIX)
add_library(tinker_crypto_a STATIC ${SOURCE_FILES} ${HEADER_FILES})
target_link_libraries(tinker_crypto_a ssl crypto)
SET_TARGET_PROPERTIES(tinker_crypto_a PROPERTIES OUTPUT_NAME "tinker_crypto")
endif()


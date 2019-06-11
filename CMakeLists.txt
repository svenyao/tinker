cmake_minimum_required(VERSION 2.8)
cmake_policy(SET CMP0015 NEW)
project(tinker)

if(UNIX)
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -O2  -Wall -std=c++11")
else()
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} /MT")
set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MTd")
set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")
endif()

if(UNIX)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/lib)
else()
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/out32)
elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
set(LIBRARY_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/out64)
endif()
endif()
set(EXECUTABLE_OUTPUT_PATH ${PROJECT_SOURCE_DIR}/out32)

include_directories(include deps/mysql/include deps/sqlite3/include deps/openssl/include deps/libscom/include)
if(UNIX)
link_directories(${PROJECT_SOURCE_DIR}/lib deps/mysql/lib deps/sqlite3/lib deps/openssl/lib)
else()
if(CMAKE_SIZEOF_VOID_P EQUAL 4)
link_directories(${PROJECT_SOURCE_DIR}/bin deps/mysql/out32 deps/sqlite3/out32 deps/openssl/out32)
elseif (CMAKE_SIZEOF_VOID_P EQUAL 8)
link_directories(${PROJECT_SOURCE_DIR}/bin deps/mysql/out64 deps/sqlite3/out64 deps/openssl/out64)
endif()
endif()

#execute_process(
#        COMMAND ln -s -f ${PROJECT_SOURCE_DIR}/deps/libevent/lib/libevent_core-2.1.so.6
#        ${PROJECT_SOURCE_DIR}/lib/libevent_core.so
#        COMMAND ln -s -f ${PROJECT_SOURCE_DIR}/deps/libevent/lib/libevent_extra-2.1.so.6
#        ${PROJECT_SOURCE_DIR}/lib/libevent_extra.so
#        COMMAND ln -s -f ${PROJECT_SOURCE_DIR}/deps/libevent/lib/libevent_pthreads-2.1.so.6
#        ${PROJECT_SOURCE_DIR}/lib/libevent_pthreads.so
#        COMMAND ln -s -f ${PROJECT_SOURCE_DIR}/deps/libevent/lib/libevent_openssl-2.1.so.6
#        ${PROJECT_SOURCE_DIR}/lib/libevent_openssl.so
#        COMMAND ln -s -f ${PROJECT_SOURCE_DIR}/deps/openssl/lib/libcrypto.so.1.1
#        ${PROJECT_SOURCE_DIR}/lib/libcrypto.so
#        COMMAND ln -s -f ${PROJECT_SOURCE_DIR}/deps/openssl/lib/libssl.so.1.1
#        ${PROJECT_SOURCE_DIR}/lib/libssl.so
#        COMMAND ln -s -f ${PROJECT_SOURCE_DIR}/deps/mysql/lib/libmysqlcppconn.so.7
#        ${PROJECT_SOURCE_DIR}/lib/libmysqlcppconn.so
#        )

add_subdirectory(src)
add_subdirectory(src/db)
#add_subdirectory(tests)

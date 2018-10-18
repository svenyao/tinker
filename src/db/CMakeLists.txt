include_directories(../../include)

if(UNIX)
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Wall -std=c++11 -static-libstdc++ -static-libgcc -fPIC")
else()
    set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -DWIN32_LEAN_AND_MEAN -D_CRT_SECURE_NO_WARNINGS
    -DCPPCONN_LIB_BUILD -DTINKER_EXPORTS")
    set(CMAKE_CXX_FLAGS_DEBUG "${CMAKE_CXX_FLAGS_DEBUG} /MD")
    set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MD")
endif()

# build tinker_db .so/.a
set(HEADER_FILES ../../include/mysql_engine.h ../../include/sqlite_engine.h)
set(SOURCE_FILES mysql_engine.cpp sqlite_engine.cpp)
# tinker_db.so
add_library(tinker_db SHARED ${SOURCE_FILES} ${HEADER_FILES})
if(UNIX)
    target_link_libraries(tinker_db mysqlcppconn-static.a sqlite3.a pthread dl)
else()
    target_link_libraries(tinker_db sqlite3 mysqlcppconn-static)
    # mysqlcppconn-static库只支持release编译，debug编译时需修改为mysqlcppconn
    set_target_properties(tinker_db PROPERTIES COMPILE_FLAGS "/wd4251 /wd4819 /wd4099 /wd4275")
endif()

if(UNIX)
    # tinker_db.a
    add_library(tinker_db_a STATIC ${SOURCE_FILES} ${HEADER_FILES})
    target_link_libraries(tinker_db_a mysqlcppconn sqlite3.a)
    SET_TARGET_PROPERTIES(tinker_db_a PROPERTIES OUTPUT_NAME "tinker_db")
endif()
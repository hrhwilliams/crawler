cmake_minimum_required(VERSION 3.10)

project(Crawler)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(SOURCE_FILES crawler2.cpp md5.c)
set(INCLUDE_DIRECTORIES .)

# target_link_libraries(Crawler PUBLIC libxml2)
find_package(LibXml2 REQUIRED)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${LIBXML2_INCLUDE_DIR})

find_package(CURL REQUIRED)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${CURL_INCLUDE_DIR})

find_package(SQLite3 REQUIRED)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${SQLITE3_INCLUDE_DIR})

add_executable(crawler ${SOURCE_FILES})
target_link_libraries(crawler PRIVATE ${LIBXML2_LIBRARIES} ${CURL_LIBRARIES} SQLite::SQLite3)

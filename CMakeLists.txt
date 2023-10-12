cmake_minimum_required(VERSION 3.10)

project(Crawler)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED True)
set(SOURCE_FILES crawler2.cpp)

# target_link_libraries(Crawler PUBLIC libxml2)
find_package(libxml2 REQUIRED)
include_directories(${CMAKE_CURRENT_SOURCE_DIR} ${LIBXML2_INCLUDE_DIR})

add_executable(Crawler ${SOURCE_FILES})
target_link_libraries(Crawler ${LIBXML2_LIBRARIES})

cmake_minimum_required(VERSION 3.20)
project(ForensicScanner VERSION 0.1.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(FS_ENABLE_QT "Build UI with Qt widgets" ON)

file(GLOB_RECURSE PROJECT_SOURCES CONFIGURE_DEPENDS
    src/*.cpp
)

set(QT_REQUIRED FALSE)
if(FS_ENABLE_QT)
    find_package(Qt6 COMPONENTS Widgets REQUIRED QUIET)
    if(Qt6Widgets_FOUND)
        set(QT_REQUIRED TRUE)
    else()
        find_package(Qt5 COMPONENTS Widgets REQUIRED QUIET)
        if(Qt5Widgets_FOUND)
            set(QT_REQUIRED TRUE)
        endif()
    endif()
endif()

if(QT_REQUIRED)
    message(STATUS "Building with Qt UI support")
    add_compile_definitions(FS_HAS_QT)
    if(Qt6Widgets_FOUND)
        set(QT_LIBS Qt6::Widgets)
    else()
        set(QT_LIBS Qt5::Widgets)
    endif()
endif()

add_executable(forensic_scanner ${PROJECT_SOURCES})

if(QT_REQUIRED)
    target_link_libraries(forensic_scanner PRIVATE ${QT_LIBS})
endif()

target_include_directories(forensic_scanner PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)

if(MSVC)
    target_compile_options(forensic_scanner PRIVATE /W4)
else()
    target_compile_options(forensic_scanner PRIVATE -Wall -Wextra -pedantic)
endif()

install(TARGETS forensic_scanner RUNTIME DESTINATION bin)

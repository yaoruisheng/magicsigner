cmake_minimum_required(VERSION 3.25)
project(MagicSigner)

set(PROJECT_SOURCES
    library.def
    library.cpp
    detours/detours.cpp
    detours/disasm.cpp
    detours/modules.cpp
)

add_library(${PROJECT_NAME} SHARED ${PROJECT_SOURCES})


target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/detours)

if(CMAKE_SIZEOF_VOID_P EQUAL 8)
    target_compile_definitions(${PROJECT_NAME} PRIVATE _M_X64 DETOURS_X64)
elseif(CMAKE_SIZEOF_VOID_P EQUAL 4)
    target_compile_definitions(${PROJECT_NAME} PRIVATE _M_IX86 DETOURS_X86)
else()
    message(FATAL_ERROR "Unknown architecture")
endif()

target_link_libraries(${PROJECT_NAME}
    Crypt32
)

set_target_properties(${PROJECT_NAME} PROPERTIES
    OUTPUT_NAME "XmlLite"
)

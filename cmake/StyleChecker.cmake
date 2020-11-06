# Syntax:
#   check_files_style(target_name [<additional files>...])
#       target_name - the name of the target whose sources will be checked
#       <additional files> - additional files to checks

find_program(STYLE_CHECKER clang-format NO_CMAKE_ENVIRONMENT_PATH)
if(NOT STYLE_CHECKER)
    message(WARNING "Style checker not found")
    return()
endif()

add_custom_target(checkstyle)

function(check_files_style target)
    get_target_property(SRCS ${target} SOURCES)

    foreach(SRC ${SRCS} ${ARGN})
        get_filename_component(SRC_FILE ${SRC} ABSOLUTE)
        string(REGEX REPLACE ${CMAKE_SOURCE_DIR} ${CMAKE_CURRENT_BINARY_DIR}/stylecheck SRC_OUT ${SRC_FILE})
        get_filename_component(SRC_DIR ${SRC_OUT} DIRECTORY)
        file(MAKE_DIRECTORY ${SRC_DIR})
        add_custom_command(OUTPUT ${SRC_OUT}
            COMMAND ${STYLE_CHECKER} -style=file ${SRC_FILE} > ${SRC_OUT}.tmp
            COMMAND ${CMAKE_COMMAND} -E compare_files ${SRC_FILE} ${SRC_OUT}.tmp
            COMMAND ${CMAKE_COMMAND} -E copy ${SRC_OUT}.tmp ${SRC_OUT}
            DEPENDS ${SRC}
            BYPRODUCTS ${SRC_OUT}.tmp
        )
        list(APPEND STYLE_CHECKER_SOURCES ${SRC_OUT})
    endforeach()

    add_custom_target(checkstyle_of_${target} DEPENDS ${STYLE_CHECKER_SOURCES})
    add_dependencies(checkstyle checkstyle_of_${target})
endfunction()

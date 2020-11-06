cmake_minimum_required(VERSION 3.9)
project(pcap_reader VERSION 0.0.1 LANGUAGES C CXX DESCRIPTION "Pcap Reader")

include(cmake/StyleChecker.cmake)

include(CTest)

set(CMAKE_C_STANDARD 99)
set(CMAKE_CXX_STANDARD 17)
add_compile_options(-Wpedantic -Werror -Wall -Wextra -Wdouble-promotion -Wno-gnu-folding-constant)

list(APPEND CMAKE_MODULE_PATH ${CMAKE_SOURCE_DIR}/cmake/)
find_package(PcapPlusPlus REQUIRED)
# or include(cmake/FindPcapPlusPlus.cmake)

find_package(Boost REQUIRED)

file(GLOB SRC app/*.cpp app/*.hpp)
add_executable(${PROJECT_NAME} ${SRC})
target_link_libraries(${PROJECT_NAME} ${Boost_LIBRARIES} PcapPlusPlus::PcapPlusPlus)
target_include_directories(${PROJECT_NAME} INTERFACE ${Boost_INCLUDE_DIRS} PRIVATE ${PcapPlusPlus_INCLUDE_DIRS})

target_compile_options(${PROJECT_NAME} PRIVATE
    -Wno-unused-parameter
    -Wno-missing-braces
    -Wno-missing-field-initializers
    -Wstrict-aliasing
    -fstrict-aliasing
)

file(GLOB HEADERS app/*.hpp)
check_files_style(${PROJECT_NAME} ${HEADERS})

# valid tests
add_test(NAME correct_file COMMAND ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/test.pcap)
add_test(NAME filter_ip COMMAND ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/test.pcap 172.16.11.1)
add_test(NAME filter_port COMMAND ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/test.pcap 53)
add_test(NAME filter_ip_port COMMAND ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/test.pcap 172.16.11.1 53)
add_test(NAME filter_port_ip COMMAND ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/test.pcap 53 172.16.11.1)

# invalid tests
add_test(NAME incorrect_file COMMAND ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/notest.pcap)
add_test(NAME filter_ip_ip COMMAND ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/test.pcap 172.16.11.1 172.16.11.2)
add_test(NAME filter_port_port COMMAND ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/test.pcap 53 54)
add_test(NAME filter_no_ip COMMAND ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/test.pcap 172.16.11.a)
add_test(NAME filter_no_port COMMAND ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/test.pcap 100000)
add_test(NAME filter_port_no_ip COMMAND ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/test.pcap 53 172.16.11.a)
add_test(NAME filter_no_port_ip COMMAND ${PROJECT_NAME} ${CMAKE_SOURCE_DIR}/test.pcap 100000 172.16.11.1)

set_tests_properties(incorrect_file
                     filter_ip_ip
                     filter_port_port
                     filter_no_ip
                     filter_no_port
                     filter_port_no_ip
                     filter_no_port_ip PROPERTIES WILL_FAIL TRUE)

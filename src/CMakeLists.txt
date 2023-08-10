cmake_minimum_required(VERSION 3.25)
project(wraptoken)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(cdt)

add_contract( wraptoken wraptoken wraptoken.cpp )
target_include_directories( wraptoken PUBLIC ${CMAKE_SOURCE_DIR}/../include )
target_ricardian_directory( wraptoken ${CMAKE_SOURCE_DIR}/../ricardian )
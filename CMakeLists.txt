cmake_minimum_required (VERSION 2.8)

set(lib_name dns)

project (${lib_name})

set(CMAKE_MODULE_PATH ${PROJECT_SOURCE_DIR}/cmake)
include(Version)

set(CMAKE_MACOSX_RPATH 0)
set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} -Wall)

find_program(CMAKE_CXX_CPPCHECK NAMES cppcheck)
if (CMAKE_CXX_CPPCHECK)
    list(
        APPEND CMAKE_CXX_CPPCHECK 
            "--enable=all"
            "--error-exitcode=1"
            "--suppress=unusedFunction"
            "--suppress=missingInclude"
            "--suppress=uselessAssignmentPtrArg"
            "--suppress=unmatchedSuppression"
            "--suppress=internalAstError"
    )
    set(CMAKE_C_CPPCHECK ${CMAKE_CXX_CPPCHECK})
else()
  message(FATAL_ERROR "Could not find the program cppcheck.")
endif()


#for ASAN
set(ASAN_OPTION "OFF" CACHE STRING " set asan type chosen by the user, using OFF as default")
set_property(CACHE ASAN_OPTION  PROPERTY STRINGS OFF ADDRESS THREAD)
message(STATUS "ASAN_OPTION='${ASAN_OPTION}'")

if(ASAN_OPTION MATCHES "ADDRESS")
    set(CMAKE_C_FLAGS "${CMAKADDRESS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=address -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
elseif(ASAN_OPTION MATCHES "THREAD")
	set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -g -DCMAKE_BUILD_TYPE=Debug -fsanitize=thread -fno-omit-frame-pointer")
	set(CMAKE_EXE_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
	set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_EXE_LINKER_FLAGS} -lasan")
endif()
# end of for ASAN

include_directories(${PROJECT_SOURCE_DIR}/include)
include_directories(/opt/MESA/include/MESA/)

file(GLOB SRC
    "src/*.cpp"
)

if(CMAKE_INSTALL_PREFIX_INITIALIZED_TO_DEFAULT)
	set(CMAKE_INSTALL_PREFIX "/opt/tsg/sapp/" CACHE PATH "default install path" FORCE)
endif()

set(DNS_DEPEND_DYN_LIB MESA_handle_logger MESA_field_stat2 MESA_prof_load)

# Shared Library Output
add_library(dns SHARED ${SRC})
set_target_properties(dns  PROPERTIES PREFIX "")
target_link_libraries(dns ${DNS_DEPEND_DYN_LIB})
if(DEFINED MESA_SHARED_INSTALL_DIR)
	set_target_properties(dns PROPERTIES OUTPUT_NAME ${lib_name} LIBRARY_OUTPUT_DIRECTORY ${MESA_SHARED_INSTALL_DIR})
else()
	set_target_properties(dns PROPERTIES OUTPUT_NAME ${lib_name})
endif()

enable_testing()
add_subdirectory(test)

set(CPACK_RPM_LIBRARIES_USER_FILELIST "%config(noreplace) ${CMAKE_INSTALL_PREFIX}/plug/protocol/dns/dns.inf"
                           	"%config(noreplace) ${CMAKE_INSTALL_PREFIX}/conf/dns/dns.conf"
			 )

install(TARGETS dns LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/protocol/dns COMPONENT LIBRARIES)
install(FILES bin/dns.inf DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/protocol/dns COMPONENT  PROFILE)
install(FILES bin/dns.conf DESTINATION ${CMAKE_INSTALL_PREFIX}/conf/dns COMPONENT  PROFILE)
install(FILES include/dns.h DESTINATION /opt/MESA/include/MESA COMPONENT HEADER)


#file(GLOB DEMO
#    "test/src/*.c"
#)

#add_library(dns_test SHARED ${DEMO})
#set_target_properties(dns_test  PROPERTIES PREFIX "")
#target_link_libraries(dns_test ${DNS_DEPEND_DYN_LIB})

#install(TARGETS dns_test LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/business/dns_test  COMPONENT LIBRARIES)
#install(FILES test/bin/dns_test.inf DESTINATION ${CMAKE_INSTALL_PREFIX}/plug/business/dns_test COMPONENT  PROFILE)

include(Package)

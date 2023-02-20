cmake_minimum_required (VERSION 2.8)

set(lib_name dns)
project(${lib_name}_test)

include(ExternalProject)
#### Protoco_test_run


ExternalProject_Add(ProtoTest PREFIX ProtoTest
        URL ${CMAKE_CURRENT_SOURCE_DIR}/test_protocol_run.zip
        URL_MD5 71d8284b59af0286b5f31f0a3160bc44  
        CMAKE_ARGS -DCMAKE_INSTALL_PREFIX=<INSTALL_DIR> -DCMAKE_BUILD_TYPE=${CMAKE_BUILD_TYPE}
    CONFIGURE_COMMAND ""
    BUILD_COMMAND ""
    INSTALL_COMMAND ""
  COMMAND ${CMAKE_COMMAND} -E make_directory <SOURCE_DIR>/conf/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/bin/${lib_name}.conf <SOURCE_DIR>/conf/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_CURRENT_SOURCE_DIR}/conflist.inf <SOURCE_DIR>/plug/
  COMMAND ${CMAKE_COMMAND} -E make_directory <SOURCE_DIR>/plug/protocol/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/bin/${lib_name}.inf <SOURCE_DIR>/plug/protocol/${lib_name}/
  COMMAND ${CMAKE_COMMAND} -E make_directory <SOURCE_DIR>/plug/business/${lib_name}_test_plug/
  COMMAND ${CMAKE_COMMAND} -E copy_if_different ${CMAKE_SOURCE_DIR}/test/${lib_name}_test_plug.inf <SOURCE_DIR>/plug/business/${lib_name}_test_plug/)

ExternalProject_Get_Property(ProtoTest INSTALL_DIR)
ExternalProject_Get_Property(ProtoTest SOURCE_DIR)
set(PROTO_TEST_RUN_DIR ${SOURCE_DIR})

add_executable(proto_test_main IMPORTED GLOBAL)
add_dependencies(proto_test_main ProtoTest)
set_property(TARGET proto_test_main PROPERTY IMPORTED_LOCATION ${SOURCE_DIR}/test_protocol_plug_main)


add_library(${lib_name}_test_plug SHARED ${lib_name}_test_plug.cpp)
target_link_libraries(${lib_name}_test_plug MESA_prof_load cjson)
set_target_properties(${lib_name}_test_plug  PROPERTIES PREFIX "")

add_test(NAME COPY_QUIC_SO COMMAND sh -c "cp ${CMAKE_BINARY_DIR}/${lib_name}.so ${PROTO_TEST_RUN_DIR}/plug/protocol/${lib_name}/${lib_name}.so")
add_test(NAME COPY_TEST_SO COMMAND sh -c "cp ${CMAKE_CURRENT_BINARY_DIR}/${lib_name}_test_plug.so ${PROTO_TEST_RUN_DIR}/plug/business/${lib_name}_test_plug/${lib_name}_test_plug.so")
add_test(NAME DNS_QUERY COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/query/query_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/query/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_CNAME COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/cname/cname_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/cname/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_NSEC_RR COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/nsec/nsec_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/nsec/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_NSEC_10_1_RR COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/nsec_10_1/nsec_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/nsec_10_1/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_NSEC3_RR COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/nsec3/nsec3_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/nsec3/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_PTR COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/ptr/ptr_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/ptr/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_SRV COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/srv/srv_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/srv/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_TXT COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/txt/txt_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/txt/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_HTTPS COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/https/https_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/https/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_CERT1 COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/cernet1/cernet1_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/cernet1/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_CERT2 COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/cernet2/cernet2_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/cernet2/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_SEC COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/dnssec/dnssec_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/dnssec/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_TCP_MULTI_TRANSCATION COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/multi_transcation/multi_transcation_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/multi_transcation/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_TCP_MULTI_PKT_TRANS_2BYTES COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/multi_pkt_trans_2bytes/multi_pkt_trans_2bytes_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/multi_pkt_trans_2bytes/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_TCP_LOST_PKT COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/tcp_lost_pkt/lost_pkt_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/tcp_lost_pkt/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})
add_test(NAME DNS_MULTI_SESSION COMMAND proto_test_main ${CMAKE_CURRENT_SOURCE_DIR}/pcap/multi_session/multi_session_result.json -f "find ${CMAKE_CURRENT_SOURCE_DIR}/pcap/multi_session/ -name *.pcap|sort -V" WORKING_DIRECTORY ${PROTO_TEST_RUN_DIR})

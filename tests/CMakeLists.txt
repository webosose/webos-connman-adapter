add_executable(test-ssid-conversion test-ssid-conversion.c
            ${CMAKE_SOURCE_DIR}/src/utils.c)
target_link_libraries(test-ssid-conversion ${GLIB2_LDFLAGS})

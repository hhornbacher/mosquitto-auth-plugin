# Try to find mosquitto

find_path(MOSQUITTO_INCLUDE_DIR 
            NAMES mosquitto.h
            HINTS $ENV{MOSQUITTO_DIR}/include
            PATHS /usr/local/include
                  /usr/include )


include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set MOSQUITTO_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(mosquitto  DEFAULT_MSG
                                  MOSQUITTO_INCLUDE_DIR)

mark_as_advanced(MOSQUITTO_INCLUDE_DIR )

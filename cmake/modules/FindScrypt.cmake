# Try to find libscrypt

find_path(SCRYPT_INCLUDE_DIR 
            NAMES libscrypt.h
            HINTS $ENV{SCRYPT_DIR}/include
            PATHS /usr/local/include
                  /usr/include )

find_library(SCRYPT_LIBRARY 
            NAMES scrypt
            HINTS $ENV{SCRYPT_DIR}/lib
            PATHS /usr/local/lib
                  /usr/lib)

include(FindPackageHandleStandardArgs)
# handle the QUIETLY and REQUIRED arguments and set SCRYPT_FOUND to TRUE
# if all listed variables are TRUE
find_package_handle_standard_args(scrypt  DEFAULT_MSG
                                  SCRYPT_LIBRARY SCRYPT_INCLUDE_DIR)

mark_as_advanced(SCRYPT_INCLUDE_DIR SCRYPT_LIBRARY )

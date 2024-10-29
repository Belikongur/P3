idf_component_register(
    SRCS "testcases.c"
    INCLUDE_DIRS "."
    REQUIRES "lownet"
    PRIV_REQUIRES "mbedtls"
)

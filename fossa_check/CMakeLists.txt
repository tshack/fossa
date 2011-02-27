cmake_minimum_required (VERSION 2.8)
Project ( fossa_check )


## CUDA STUFF ##########################################
FIND_PACKAGE (CUDA REQUIRED)
IF (CUDA_FOUND)
    CUDA_INCLUDE_DIRECTORIES (
        ${CMAKE_CURRENT_SOURCE_DIR}
    )
ENDIF (CUDA_FOUND)
########################################################


## BUILD TARGET SOURCE FILES ###########################
SET ( SRC_FCHECK
    fossa_check.cu
)
########################################################


## BUILD TARGETS #######################################
CUDA_ADD_EXECUTABLE (
    fossa_check
    ${SRC_FCHECK}
)
########################################################


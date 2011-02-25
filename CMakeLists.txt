#  This file is part of fossa
#  Copyright (C) 2011  James A. Shackleford
#
#  fossa is free software: you can redistribute it and/or modify
#  it under the terms of the GNU General Public License as published by
#  the Free Software Foundation, either version 3 of the License, or
#  (at your option) any later version.
#
#  This program is distributed in the hope that it will be useful,
#  but WITHOUT ANY WARRANTY; without even the implied warranty of
#  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
#  GNU General Public License for more details.
#
#  You should have received a copy of the GNU General Public License
#  along with this program.  If not, see <http://www.gnu.org/licenses/>.

cmake_minimum_required (VERSION 2.8)
Project ( fossa )

SET (CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/cmake" ${CMAKE_MODULE_PATH})

##-----------------------------------------------------------------------------
##  Detect 32-bit or 64-bit machine
##-----------------------------------------------------------------------------
IF (NOT APPLE)
  IF (CMAKE_SIZEOF_VOID_P EQUAL 4)
    SET (_arch_i386_ TRUE)
    SET (_arch_x86_64_ FALSE)
    MESSAGE (STATUS "Machine arch is i386")
  ELSE (CMAKE_SIZEOF_VOID_P EQUAL 4)
    SET (_arch_i386_ FALSE)
    SET (_arch_x86_64_ TRUE)
    MESSAGE (STATUS "Machine arch is x86_64")
  ENDIF (CMAKE_SIZEOF_VOID_P EQUAL 4)
ENDIF (NOT APPLE)

INCLUDE_DIRECTORIES (BEFORE ${CMAKE_CURRENT_SOURCE_DIR})
INCLUDE_DIRECTORIES (BEFORE ${CMAKE_BINARY_DIR})

## FANCY SUBVERSION STUFF ##############################
FIND_PACKAGE (SVN)
IF (SUBVERSION_FOUND)
    SUBVERSION_WC_INFO (${CMAKE_CURRENT_SOURCE_DIR} FOSSA)
    SET (SVN_REV ${FOSSA_WC_REVISION})
    MESSAGE("-- Current revision is ${SVN_REV}") 
ENDIF (SUBVERSION_FOUND)
########################################################


## LIBCUZMEM ###########################################
ADD_SUBDIRECTORY (libcuzmem)
ADD_CUSTOM_COMMAND (
    OUTPUT "${CMAKE_BINARY_DIR}/libcuzmem.so"
    COMMAND
    ${CMAKE_COMMAND} "-E" "copy"
    "${CMAKE_BINARY_DIR}/libcuzmem/libcuzmem.so"
    "${CMAKE_BINARY_DIR}/libcuzmem.so"
    DEPENDS cuzmem
)
ADD_CUSTOM_TARGET (libcuzmem
    DEPENDS "${CMAKE_BINARY_DIR}/libcuzmem.so"
)
########################################################


## LIBGCRYPT ###########################################
FIND_PACKAGE (libgcrypt REQUIRED)

IF (LIBGCRYPT_FOUND)
    INCLUDE_DIRECTORIES (${LIBGCRYPT_INCLUDE_DIR})
    LINK_LIBRARIES (${LIBGCRYPT_LIBRARY})
ENDIF (LIBGCRYPT_FOUND)
########################################################

CONFIGURE_FILE (
    ${CMAKE_CURRENT_SOURCE_DIR}/fossa.h.in
    ${CMAKE_CURRENT_BINARY_DIR}/fossa.h
)

## BUILD TARGET SOURCE FILES ###########################
SET ( SRC_fossa
    fossa.c
    options.c
    ptrace_wrap.c
    elf_tools.c
    child_tools.c
    inject.c
    hash.c
)
########################################################


## BUILD TARGETS #######################################
ADD_EXECUTABLE ( fossa
    ${SRC_fossa}
)
ADD_DEPENDENCIES (fossa libcuzmem)
########################################################

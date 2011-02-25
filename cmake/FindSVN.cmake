# - Extract information from a subversion working copy
# The module defines the following variables:
#  SUBVERSION_SVN_EXECUTABLE - path to svn command line client
#  SUBVERSION_VERSION_SVN - version of svn command line client
#  SUBVERSION_FOUND - true if the command line client was found
# If the command line client executable is found the macro
#  SUBVERSION_WC_INFO(<dir> <var-prefix>)
# is defined to extract information of a subversion working copy at
# a given location. The macro defines the following variables:
#  <var-prefix>_WC_URL - url of the repository (at <dir>)
#  <var-prefix>_WC_ROOT - root url of the repository
#  <var-prefix>_WC_REVISION - current revision
#  <var-prefix>_WC_LAST_CHANGED_AUTHOR - author of last commit
#  <var-prefix>_WC_LAST_CHANGED_DATE - date of last commit
#  <var-prefix>_WC_LAST_CHANGED_REV - revision of last commit
#  <var-prefix>_WC_LAST_CHANGED_LOG - last log of base revision
#  <var-prefix>_WC_INFO - output of command `svn info <dir>'
# Example usage:
#  FIND_PACKAGE(SUBVERSION)
#  IF(SUBVERSION_FOUND)
#    SUBVERSION_WC_INFO(${PROJECT_SOURCE_DIR} Project)
#    MESSAGE("Current revision is ${Project_WC_REVISION}")
#    SUBVERSION_WC_LOG(${PROJECT_SOURCE_DIR} Project)
#    MESSAGE("Last changed log is ${Project_LAST_CHANGED_LOG}")
#  ENDIF(SUBVERSION_FOUND)

# Copyright (c) 2006, Tristan Carel
# All rights reserved.
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
#     * Redistributions of source code must retain the above copyright
#       notice, this list of conditions and the following disclaimer.
#     * Redistributions in binary form must reproduce the above copyright
#       notice, this list of conditions and the following disclaimer in the
#       documentation and/or other materials provided with the distribution.
#     * Neither the name of the University of California, Berkeley nor the
#       names of its contributors may be used to endorse or promote products
#       derived from this software without specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND ANY
# EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
# WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
# DISCLAIMED. IN NO EVENT SHALL THE REGENTS AND CONTRIBUTORS BE LIABLE FOR ANY
# DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
# (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
# LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND
# ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
# (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
# SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

# $Id: FindSUBVERSION.cmake,v 1.2.2.3 2008-05-23 20:09:34 hoffman Exp $

SET(SUBVERSION_FOUND FALSE)
SET(SUBVERSION_SVN_FOUND FALSE)

FIND_PROGRAM(SUBVERSION_SVN_EXECUTABLE 
  NAMES svn C:/cygwin/bin/svn 
  DOC "subversion command line client")
FIND_PROGRAM(SUBVERSION_SVNVERSION_EXECUTABLE 
  NAMES svnversion C:/cygwin/bin/svnversion
  DOC "subversion svnversion program")
MARK_AS_ADVANCED(SUBVERSION_SVN_EXECUTABLE)
MARK_AS_ADVANCED(SUBVERSION_SVNVERSION_EXECUTABLE)

IF(SUBVERSION_SVN_EXECUTABLE)
  SET(SUBVERSION_SVN_FOUND TRUE)
  SET(SUBVERSION_FOUND TRUE)

  MACRO(SUBVERSION_WC_INFO dir prefix)
    # the subversion commands should be executed with the C locale, otherwise
    # the message (which are parsed) may be translated, Alex
    SET(_SUBVERSION_SAVED_LC_ALL "$ENV{LC_ALL}")
    SET(ENV{LC_ALL} C)

    EXECUTE_PROCESS(COMMAND ${SUBVERSION_SVN_EXECUTABLE} --version
      WORKING_DIRECTORY ${dir}
      OUTPUT_VARIABLE SUBVERSION_VERSION_SVN
      OUTPUT_STRIP_TRAILING_WHITESPACE)

    EXECUTE_PROCESS(COMMAND ${SUBVERSION_SVN_EXECUTABLE} info ${dir}
      OUTPUT_VARIABLE ${prefix}_WC_INFO
      ERROR_VARIABLE SUBVERSION_svn_info_error
      RESULT_VARIABLE SUBVERSION_svn_info_result
      OUTPUT_STRIP_TRAILING_WHITESPACE)

    IF(NOT ${SUBVERSION_svn_info_result} EQUAL 0)
      MESSAGE(SEND_ERROR "Command \"${SUBVERSION_SVN_EXECUTABLE} info ${dir}\" failed with output:\n${SUBVERSION_svn_info_error}")
    ELSE(NOT ${SUBVERSION_svn_info_result} EQUAL 0)

      STRING(REGEX REPLACE "^(.*\n)?svn, version ([.0-9]+).*"
        "\\2" SUBVERSION_VERSION_SVN "${SUBVERSION_VERSION_SVN}")
      STRING(REGEX REPLACE "^(.*\n)?URL: ([^\n]+).*"
        "\\2" ${prefix}_WC_URL "${${prefix}_WC_INFO}")
      STRING(REGEX REPLACE "^(.*\n)?Revision: ([^\n]+).*"
        "\\2" ${prefix}_WC_REVISION "${${prefix}_WC_INFO}")
      STRING(REGEX REPLACE "^(.*\n)?Last Changed Author: ([^\n]+).*"
        "\\2" ${prefix}_WC_LAST_CHANGED_AUTHOR "${${prefix}_WC_INFO}")
      STRING(REGEX REPLACE "^(.*\n)?Last Changed Rev: ([^\n]+).*"
        "\\2" ${prefix}_WC_LAST_CHANGED_REV "${${prefix}_WC_INFO}")
      STRING(REGEX REPLACE "^(.*\n)?Last Changed Date: ([^\n]+).*"
        "\\2" ${prefix}_WC_LAST_CHANGED_DATE "${${prefix}_WC_INFO}")

    ENDIF(NOT ${SUBVERSION_svn_info_result} EQUAL 0)

    # restore the previous LC_ALL
    SET(ENV{LC_ALL} ${_SUBVERSION_SAVED_LC_ALL})

  ENDMACRO(SUBVERSION_WC_INFO)

  MACRO(SUBVERSION_WC_LOG dir prefix)
    # This macro can block if the certificate is not signed:
    # svn ask you to accept the certificate and wait for your answer
    # This macro requires a svn server network access (Internet most of the time)
    # and can also be slow since it access the svn server
    EXECUTE_PROCESS(COMMAND
      ${SUBVERSION_SVN_EXECUTABLE} log -r BASE ${dir}
      OUTPUT_VARIABLE ${prefix}_LAST_CHANGED_LOG
      ERROR_VARIABLE SUBVERSION_svn_log_error
      RESULT_VARIABLE SUBVERSION_svn_log_result
      OUTPUT_STRIP_TRAILING_WHITESPACE)

    IF(NOT ${SUBVERSION_svn_log_result} EQUAL 0)
      MESSAGE(SEND_ERROR "Command \"${SUBVERSION_SVN_EXECUTABLE} log -r BASE ${dir}\" failed with output:\n${SUBVERSION_svn_log_error}")
    ENDIF(NOT ${SUBVERSION_svn_log_result} EQUAL 0)
  ENDMACRO(SUBVERSION_WC_LOG)

ENDIF(SUBVERSION_SVN_EXECUTABLE)

IF(NOT SUBVERSION_FOUND)
  IF(NOT SUBVERSION_FIND_QUIETLY)
    MESSAGE(STATUS "SUBVERSION was not found.")
  ELSE(NOT SUBVERSION_FIND_QUIETLY)
    IF(SUBVERSION_FIND_REQUIRED)
      MESSAGE(FATAL_ERROR "SUBVERSION was not found.")
    ENDIF(SUBVERSION_FIND_REQUIRED)
  ENDIF(NOT SUBVERSION_FIND_QUIETLY)
ENDIF(NOT SUBVERSION_FOUND)

# FindSUBVERSION.cmake ends here.

#
# arm.cmake: toolchain file for ARM testing
#
# SPDX-License-Identifier: BSD-3-Clause
#
# This file is part of Sweet B, a safe, compact, embeddable library for
# elliptic curve cryptography.
#
# https://github.com/westerndigitalcorporation/sweet-b
#
# Copyright (c) 2020 Western Digital Corporation or its affiliates.
#
# Redistribution and use in source and binary forms, with or without
# modification, are permitted provided that the following conditions are met:
#
# 1. Redistributions of source code must retain the above copyright notice,
# this list of conditions and the following disclaimer.
#
# 2. Redistributions in binary form must reproduce the above copyright notice,
# this list of conditions and the following disclaimer in the documentation
# and/or other materials provided with the distribution.
#
# 3. Neither the name of the copyright holder nor the names of its contributors
# may be used to endorse or promote products derived from this software without
# specific prior written permission.
#
# THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
# AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
# IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
# ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE
# LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
# CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
# SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
# INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
# CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
# ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
# POSSIBILITY OF SUCH DAMAGE.
#

SET(CMAKE_C_COMPILER arm-linux-gnueabihf-gcc)
SET(CMAKE_C_FLAGS "-Os -mcpu=cortex-a5 -mthumb" CACHE STRING "" FORCE)
SET(CMAKE_EXE_LINKER_FLAGS "-static" CACHE STRING "" FORCE)
SET(SB_TEST_WORD_SIZE "4" CACHE STRING "")
SET(SB_TEST_VERIFY_QR "0" CACHE STRING "")
SET(SB_LIBRARY_DEFINES "SB_UNROLL=3" CACHE STRING "")
SET(SB_FE_ASM "1" CACHE STRING "")
SET(SB_ASM_SOURCES "src/sb_fe_armv7.s" CACHE STRING "")

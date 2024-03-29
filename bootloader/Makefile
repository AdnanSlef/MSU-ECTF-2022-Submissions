#  2022 eCTF
#  Bootloader Makefile
#  Kyle Scaplen
#
#  (c) 2022 The MITRE Corporation
#
# This source file is part of an example system for MITRE's 2022 Embedded System CTF (eCTF).
# This code is being provided only for educational purposes for the 2022 MITRE eCTF competition,
# and may not meet MITRE standards for quality. Use this code at your own risk!

# define the part type and base directory - must be defined for makedefs to work
PART=TM4C123GH6PM
CFLAGSgcc=-DTARGET_IS_TM4C123_RB1
ROOT=.

# Uncomment to enable debug symbols
DEBUG=1

# additional base directories
TIVA_ROOT=${ROOT}/lib/tivaware

# add additional directories to search for source files to VPATH
VPATH=${ROOT}/src
VPATH+=${TIVA_ROOT}

# add additional directories to search for header files to IPATH
IPATH=${ROOT}/inc
IPATH+=${TIVA_ROOT}

# Include common makedefs
include ${TIVA_ROOT}/makedefs

# add initial firmware version
CFLAGS+=-DOLDEST_VERSION=${OLDEST_VERSION}

# this rule must come first in `all`
all: ${COMPILER}

# this must be the last build rule of `all`
all: ${COMPILER}/bootloader.axf


################  start  symmetric encryption ################
DO_MAKE_GCM=yes
ifdef DO_MAKE_GCM
GCMPATH=${ROOT}/lib/SharedAES-GCM

# add compiler flag to enable test GCM code 
CFLAGS+=-DTEST_GCM

# add path to crypto source files to source path
VPATH+=${GCMPATH}

# add gcm library to includes path
IPATH+=${GCMPATH}

# add rule to build gcm library
${COMPILER}/bootloader.axf: ${COMPILER}/aead.o ${COMPILER}/gcmtest.o ${COMPILER}/gcm.o ${COMPILER}/aes.o

endif
################   end   symmetric encryption ################


################  start  digital signature ################
DO_MAKE_SWEET_B=yes
ifdef DO_MAKE_SWEET_B

# add compiler flag to enable test SB code 
CFLAGS+=-DTEST_SB

SBPATH=${ROOT}/lib/sweet-b

# add path to crypto source files to source path
VPATH+=${SBPATH}/src
VPATH+=${SBPATH}/include

# add gcm library to includes path
IPATH+=${SBPATH}/include
IPATH+=${SBPATH}/src

# TODO limit word size to fit processor
#CFLAGS+=-DSB_WORD_SIZE=2

#disable the unused curve
CFLAGS+=-DSB_SW_SECP256K1_SUPPORT=0

# add rule to build sb library
${COMPILER}/bootloader.axf: ${COMPILER}/sb_sha256.o ${COMPILER}/sb_fe.o ${COMPILER}/sb_sw_lib.o ${COMPILER}/sb_hmac_drbg.o ${COMPILER}/sb_hmac_sha256.o ${COMPILER}/sb_hkdf.o

endif
################   end   digital signature ################

#TODO optimize for speed
#CFLAGS+=-O2

# build libraries
${TIVA_ROOT}/driverlib/${COMPILER}/libdriver.a:
	${MAKE} -C ${TIVA_ROOT}/driverlib

tivaware: ${TIVA_ROOT}/driverlib/${COMPILER}/libdriver.a

# clean the libraries
clean_tivaware:
	${MAKE} -C ${TIVA_ROOT}/driverlib clean

# clean all build products
clean: clean_tivaware
	@rm -rf ${COMPILER} ${wildcard *~}

# create the output directory
${COMPILER}:
	@mkdir ${COMPILER}


# check that parameters are defined
check_defined = \
	$(strip $(foreach 1,$1, \
		$(call __check_defined,$1)))
__check_defined = \
	$(if $(value $1),, \
	  $(error Undefined $1))
arg_check:
	$(call check_defined, OLDEST_VERSION)


# for each source file that needs to be compiled besides the file that defines `main`

# Check arguments
${COMPILER}/bootloader.axf: arg_check
${COMPILER}/bootloader.axf: ${COMPILER}/flash.o
${COMPILER}/bootloader.axf: ${COMPILER}/uart.o
${COMPILER}/bootloader.axf: ${COMPILER}/bootloader.o
${COMPILER}/bootloader.axf: ${COMPILER}/startup_${COMPILER}.o
${COMPILER}/bootloader.axf: ${TIVA_ROOT}/driverlib/${COMPILER}/libdriver.a


SCATTERgcc_bootloader=${TIVA_ROOT}/bootloader.ld
ENTRY_bootloader=Bootloader_Startup

# Include the automatically generated dependency files.
ifneq (${MAKECMDGOALS},clean)
-include ${wildcard ${COMPILER}/*.d} __dummy__
endif

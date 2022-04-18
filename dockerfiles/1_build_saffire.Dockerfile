# 2022 eCTF
# Spartans
# Host-Tools and Bootloader Creation Dockerfile

FROM ubuntu:focal

# Add environment customizations here
# NOTE: do this first so Docker can used cached containers to skip reinstalling everything
RUN apt-get update && apt-get upgrade -y && \
    apt-get install -y python3 \
    binutils-arm-none-eabi gcc-arm-none-eabi make \
    openssl python3-pip && \
    pip3 install pycryptodome

# Create bootloader binary folder
RUN mkdir /bootloader

# Add any system-wide secrets here
RUN mkdir /secrets

# Add host tools and bootloader source to container
ADD host_tools/ /host_tools
ADD bootloader /bl_build

# Skip cache from here on
ADD "https://www.random.org/cgi-bin/randbyte?nbytes=10&format=h" skipcache

# Generate Secrets
RUN sh /host_tools/generate_secrets

# Create EEPROM contents
RUN sh /host_tools/build_eeprom

# Compile bootloader
WORKDIR /bl_build

ARG OLDEST_VERSION
RUN make OLDEST_VERSION=${OLDEST_VERSION}
RUN mv /bl_build/gcc/bootloader.bin /bootloader/bootloader.bin
RUN mv /bl_build/gcc/bootloader.axf /bootloader/bootloader.elf

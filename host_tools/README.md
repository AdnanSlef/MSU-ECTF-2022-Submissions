# Host Tools

This folder holds all of the host tools. It includes the build process (see `1_build_saffire.Dockerfile`) as well as other tools for interacting with the SAFFIRe bootloader and avionics device. These tools are run from within the Host Container, and interact with the physical or emulated microcontroller over UART.
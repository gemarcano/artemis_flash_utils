![generate executables](https://github.com/sparkfun/Apollo3_Uploader_SVL/workflows/generate%20executables/badge.svg)

# Apollo3 Uploaders - SparkFun Variable Loader (SVL) and Ambiq Secure Bootloader (ASB)

This repository packages up the [upstream SVL flasher application](https://github.com/sparkfun/Apollo3_Uploader_SVL) and [ASB programmer](https://github.com/sparkfun/Apollo3_Uploader_ASB) in a more typical python package.

The ```svl``` bootloader is the default bootloader on Artemis module--based boards. This repo contains both the Python programs that are used to send code to a board and the source code for the program that receives code on an Artemis module.

The ```asb``` bootloader is part of the Apollo3 silicon, and is controlled by the Info0 OTP registers. As Sparkfun has it configured, it is not using Secure Boot, and on exit it looks at the flat binary at location `0xC000` in flash. It will check the stack pointer at `0xC000` then jump to the "reset" vector at location `0xC004`.

The bootloader for the Artemis can be upgraded via Arduino using [these instructions](https://learn.sparkfun.com/tutorials/designing-with-the-sparkfun-artemis/all#troubleshooting). It can also be upgraded using the [Artemis Firmware Upload GUI](https://github.com/sparkfun/Artemis-Firmware-Upload-GUI).

Artemis SVL Versions:

* v5 - Speed and reliability increases
* v4 - Added peripheral deinitialization to deliver the Apollo3 closer to the initial reset state.
* v3 - Initial version

# Usage

* prerequisites
  * board has the SparkFun Variable Loader installed
    * source code is located in ```bootloader/src```
    * precompiled binaries and a makefile are located in ```bootloader/gcc```
      (the artemis module target is suitable for all current SparkFun products)
  * Python is installed on your computer
  * your program is compiled + linked to support the SVL (binary offset ```0x10000```)
* use the SVL loader script to upload to the board

  ```python svl.py [flags] port```
  
  * ```-b``` **baud rate**: 115200, 921600, or other desired common baud rate (57600, 115200, 230400, 460800, 921600)
  * ```-f``` **filepath**: path to the binary image of your program to upload
  * ```port``` **serial port**: the serial port to connect over (*/dev/\** on \*nix or *COMX* on windows)
  * ```-v``` **verbose**: turn on verbose output

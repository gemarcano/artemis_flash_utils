#!/usr/bin/env python3
"""Ambiq Secure Bootloader programmer.

Combination of the three steps to take an 'application.bin' file and run it on
a SparkFun Artemis module

Information:
  This script performs the three main tasks:
      1. Convert 'application.bin' to an OTA update blob
      2. Convert the OTA blob into a wired update blob
      3. Push the wired update blob into the Artemis module
"""

import os
import sys
import time
import logging
import argparse

import serial
from serial.tools import list_ports

# from asb.am_defines import *
import asb.am_defines as defs
from asb.keys_info import (
    KEY_TBL_AES,
    KEY_TBL_HMAC,
    MIN_AES_KEY_IDX,
    MAX_AES_KEY_IDX,
    MIN_HMAC_KEY_IDX,
    MAX_HMAC_KEY_IDX,
    INFO_KEY,
    FLASH_KEY,
)

# ******************************************************************************
#
# Global Variables
#
# ******************************************************************************
load_tries = 0  # If we fail, try again. Tracks the number of tries we've attempted
load_success = False
blob2wiredfile = ""
uploadbinfile = ""


def bin2blob_process(
    loadaddress,
    app_file,
    magic_num,
    crc_i,
    crc_b,
    auth_i,
    auth_b,
    protection,
    auth_key_idx,
    output,
    enc_key_idx,
    version,
    erase_prev,
    child0,
    child1,
    authalgo,
    encalgo,
):
    """Generate the image blob as per command line parameters."""
    app_binarray = bytearray()
    # Open the file, and read it into an array of integers.
    with app_file as f_app:
        app_binarray.extend(f_app.read())
        f_app.close()

    enc_val = 0
    if encalgo != 0:
        enc_val = 1
        if (enc_key_idx < MIN_AES_KEY_IDX) or (enc_key_idx > MAX_AES_KEY_IDX):
            defs.am_print(
                "Invalid encKey Idx ", enc_key_idx, level=defs.AM_PRINT_LEVEL_ERROR
            )
            return
        if encalgo == 2:
            if enc_key_idx & 0x1:
                defs.am_print(
                    "Invalid encKey Idx ", enc_key_idx, level=defs.AM_PRINT_LEVEL_ERROR
                )
                return
            key_size = 32
        else:
            key_size = 16
    if authalgo != 0:
        if (
            (auth_key_idx < MIN_HMAC_KEY_IDX)
            or (auth_key_idx > MAX_HMAC_KEY_IDX)
            or (auth_key_idx & 0x1)
        ):
            defs.am_print(
                "Invalid authKey Idx ", auth_key_idx, level=defs.AM_PRINT_LEVEL_ERROR
            )
            return

    if magic_num == defs.AM_IMAGE_MAGIC_MAIN:
        hdr_length = defs.AM_IMAGEHDR_SIZE_MAIN
        # fixed header length
    elif magic_num in (
        defs.AM_IMAGE_MAGIC_CHILD,
        defs.AM_IMAGE_MAGIC_CUSTPATCH,
        defs.AM_IMAGE_MAGIC_NONSECURE,
        defs.AM_IMAGE_MAGIC_INFO0,
    ):
        hdr_length = defs.AM_IMAGEHDR_SIZE_AUX
        # fixed header length
    else:
        defs.am_print(
            "magic number",
            hex(magic_num),
            " not supported",
            level=defs.AM_PRINT_LEVEL_ERROR,
        )
        return
    defs.am_print("Header Size = %s", hex(hdr_length))

    # generate mutable byte array for the header
    hdr_binarray = bytearray([0x00] * hdr_length)

    orig_app_length = len(app_binarray)
    defs.am_print("original app_size ", hex(orig_app_length), "(", orig_app_length, ")")

    defs.am_print("load_address ", hex(loadaddress), "(", loadaddress, ")")
    if loadaddress & 0x3:
        defs.am_print(
            "load address needs to be word aligned", level=defs.AM_PRINT_LEVEL_ERROR
        )
        return

    if magic_num == defs.AM_IMAGE_MAGIC_INFO0:
        if orig_app_length & 0x3:
            defs.am_print(
                "INFO0 blob length needs to be multiple of 4",
                level=defs.AM_PRINT_LEVEL_ERROR,
            )
            return
        if (loadaddress + orig_app_length) > defs.INFO_SIZE_BYTES:
            defs.am_print(
                "INFO0 Offset and length exceed size", level=defs.AM_PRINT_LEVEL_ERROR
            )
            return

    if enc_val == 1:
        block_size = defs.AM_SECBOOT_AESCBC_BLOCK_SIZE_BYTES
        app_binarray = defs.pad_to_block_size(app_binarray, block_size, 1)
    else:
        # Add Padding
        app_binarray = defs.pad_to_block_size(app_binarray, 4, 0)

    app_length = len(app_binarray)
    defs.am_print("app_size ", hex(app_length), "(", app_length, ")")

    # Create Image blobs

    # w0
    blob_len = hdr_length + app_length
    w0 = (magic_num << 24) | ((enc_val & 0x1) << 23) | blob_len

    defs.am_print("w0 =", hex(w0))
    defs.fill_word(hdr_binarray, 0, w0)

    # w2
    security_val = ((auth_i << 1) | crc_i) << 4 | (auth_b << 1) | crc_b
    defs.am_print("Security Value ", hex(security_val))
    w2 = (
        ((security_val << 24) & 0xFF000000)
        | ((authalgo) & 0xF)
        | ((auth_key_idx << 4) & 0xF0)
        | ((encalgo << 8) & 0xF00)
        | ((enc_key_idx << 12) & 0xF000)
    )
    defs.fill_word(hdr_binarray, 8, w2)
    defs.am_print("w2 = %s", hex(w2))

    if magic_num == defs.AM_IMAGE_MAGIC_INFO0:
        # Insert the INFO0 size and offset
        addr_word = ((orig_app_length >> 2) << 16) | ((loadaddress >> 2) & 0xFFFF)
        version_key_word = INFO_KEY
    else:
        # Insert the application binary load address.
        addr_word = loadaddress | (protection & 0x3)
        # Initialize version_key_word
        version_key_word = (version & 0x7FFF) | ((erase_prev & 0x1) << 15)

    defs.am_print("addr_word = %s", hex(addr_word))
    defs.fill_word(hdr_binarray, defs.AM_IMAGEHDR_OFFSET_ADDR, addr_word)

    defs.am_print("version_key_word = %s", hex(version_key_word))
    defs.fill_word(hdr_binarray, defs.AM_IMAGEHDR_OFFSET_VERKEY, version_key_word)

    # Initialize child (Child Ptr/ Feature key)
    defs.am_print("child0/feature = %s", hex(child0))
    defs.fill_word(hdr_binarray, defs.AM_IMAGEHDR_OFFSET_CHILDPTR, child0)
    defs.am_print("child1 = %s", hex(child1))
    defs.fill_word(hdr_binarray, defs.AM_IMAGEHDR_OFFSET_CHILDPTR + 4, child1)

    auth_key_idx = auth_key_idx - MIN_HMAC_KEY_IDX
    if auth_b != 0:  # Authentication needed
        defs.am_print("Boot Authentication Enabled")
        # Initialize the clear image HMAC
        sig_clr = defs.compute_hmac(
            KEY_TBL_HMAC[
                auth_key_idx
                * defs.AM_SECBOOT_KEYIDX_BYTES : (
                    auth_key_idx * defs.AM_SECBOOT_KEYIDX_BYTES + defs.AM_HMAC_SIG_SIZE
                )
            ],
            (hdr_binarray[defs.AM_IMAGEHDR_START_HMAC : hdr_length] + app_binarray),
        )
        defs.am_print("HMAC Clear")
        defs.am_print([hex(n) for n in sig_clr])
        # Fill up the HMAC
        for x in range(0, defs.AM_HMAC_SIG_SIZE):
            hdr_binarray[defs.AM_IMAGEHDR_OFFSET_SIGCLR + x] = sig_clr[x]

    # All the header fields part of the encryption are now final
    if enc_val == 1:
        defs.am_print("Encryption Enabled")
        enc_key_idx = enc_key_idx - MIN_AES_KEY_IDX
        iv_val_aes = os.urandom(defs.AM_SECBOOT_AESCBC_BLOCK_SIZE_BYTES)
        defs.am_print("Initialization Vector")
        defs.am_print(
            [
                hex(iv_val_aes[n])
                for n in range(0, defs.AM_SECBOOT_AESCBC_BLOCK_SIZE_BYTES)
            ]
        )
        key_aes = os.urandom(key_size)
        defs.am_print("AES Key used for encryption")
        defs.am_print([hex(key_aes[n]) for n in range(0, key_size)])
        # Encrypted Part
        defs.am_print(
            "Encrypting blob of size ",
            (hdr_length - defs.AM_IMAGEHDR_START_ENCRYPT + app_length),
        )
        enc_binarray = defs.encrypt_app_aes(
            (hdr_binarray[defs.AM_IMAGEHDR_START_ENCRYPT : hdr_length] + app_binarray),
            key_aes,
            iv_val_aes,
        )
        # Encrypted Key
        enc_key = defs.encrypt_app_aes(
            key_aes,
            KEY_TBL_AES[enc_key_idx * key_size : enc_key_idx * key_size + key_size],
            defs.IV_VAL_0,
        )
        defs.am_print("Encrypted Key")
        defs.am_print([hex(enc_key[n]) for n in range(0, key_size)])
        # Fill up the IV
        for x in range(0, defs.AM_SECBOOT_AESCBC_BLOCK_SIZE_BYTES):
            hdr_binarray[defs.AM_IMAGEHDR_OFFSET_IV + x] = iv_val_aes[x]
        # Fill up the Encrypted Key
        for x in range(0, key_size):
            hdr_binarray[defs.AM_IMAGEHDR_OFFSET_KEK + x] = enc_key[x]
    else:
        enc_binarray = (
            hdr_binarray[defs.AM_IMAGEHDR_START_ENCRYPT : hdr_length] + app_binarray
        )

    if auth_i != 0:  # Install Authentication needed
        defs.am_print("Install Authentication Enabled")
        # Initialize the top level HMAC
        sig = defs.compute_hmac(
            KEY_TBL_HMAC[
                auth_key_idx
                * defs.AM_SECBOOT_KEYIDX_BYTES : (
                    auth_key_idx * defs.AM_SECBOOT_KEYIDX_BYTES + defs.AM_HMAC_SIG_SIZE
                )
            ],
            (
                hdr_binarray[
                    defs.AM_IMAGEHDR_START_HMAC_INST : defs.AM_IMAGEHDR_START_ENCRYPT
                ]
                + enc_binarray
            ),
        )
        defs.am_print("Generated Signature")
        defs.am_print([hex(n) for n in sig])
        # Fill up the HMAC
        for x in range(0, defs.AM_HMAC_SIG_SIZE):
            hdr_binarray[defs.AM_IMAGEHDR_OFFSET_SIG + x] = sig[x]
    # compute the CRC for the blob - this is done on a clear image
    crc = defs.crc32(
        hdr_binarray[defs.AM_IMAGEHDR_START_CRC : hdr_length] + app_binarray
    )
    defs.am_print("crc =  ", hex(crc))
    w1 = crc
    defs.fill_word(hdr_binarray, defs.AM_IMAGEHDR_OFFSET_CRC, w1)

    # now output all three binary arrays in the proper order
    output = output + "_OTA_blob.bin"

    global blob2wiredfile
    blob2wiredfile = output  # save the output of bin2blob for use by blob2wired
    defs.am_print("Writing to file ", output)
    with open(output, mode="wb") as out:
        out.write(hdr_binarray[0 : defs.AM_IMAGEHDR_START_ENCRYPT])
        out.write(enc_binarray)


def blob2wired_process(
    app_file,
    imagetype,
    loadaddress,
    authalgo,
    encalgo,
    auth_key_idx,
    enc_key_idx,
    options_val,
    max_size,
    output,
):
    """Generate the image blob as per command line parameters."""
    global uploadbinfile

    app_binarray = bytearray()
    # Open the file, and read it into an array of integers.
    print("testing: " + app_file)
    with open(app_file, "rb") as f_app:
        app_binarray.extend(f_app.read())
        f_app.close()

    # Make sure it is page multiple
    if (max_size & (defs.FLASH_PAGE_SIZE - 1)) != 0:
        defs.am_print(
            "split needs to be multiple of flash page size",
            level=defs.AM_PRINT_LEVEL_ERROR,
        )
        return

    if encalgo != 0:
        if (enc_key_idx < MIN_AES_KEY_IDX) or (enc_key_idx > MAX_AES_KEY_IDX):
            defs.am_print(
                "Invalid encKey Idx ", enc_key_idx, level=defs.AM_PRINT_LEVEL_ERROR
            )
            return
        if encalgo == 2:
            if enc_key_idx & 0x1:
                defs.am_print(
                    "Invalid encKey Idx ", enc_key_idx, level=defs.AM_PRINT_LEVEL_ERROR
                )
                return
            key_size = 32
        else:
            key_size = 16
    if authalgo != 0:
        if (
            (auth_key_idx < MIN_HMAC_KEY_IDX)
            or (auth_key_idx > MAX_HMAC_KEY_IDX)
            or (auth_key_idx & 0x1)
        ):
            defs.am_print(
                "Invalid authKey Idx ", auth_key_idx, level=defs.AM_PRINT_LEVEL_ERROR
            )
            return

    hdr_length = defs.AM_WU_IMAGEHDR_SIZE
    # fixed header length
    defs.am_print("Header Size = %s", hex(hdr_length))

    orig_app_length = len(app_binarray)
    logging.debug("Origian app length: %s", orig_app_length)

    if encalgo != 0:
        block_size = key_size
        app_binarray = defs.pad_to_block_size(app_binarray, block_size, 1)
    else:
        # Add Padding
        app_binarray = defs.pad_to_block_size(app_binarray, 4, 0)

    app_length = len(app_binarray)
    defs.am_print("app_size ", hex(app_length), "(", app_length, ")")

    if app_length + hdr_length > max_size:
        defs.am_print("Image size bigger than max - Creating Split image")

    start = 0
    # now output all three binary arrays in the proper order
    output = output + "_Wired_OTA_blob.bin"
    uploadbinfile = output
    # save the name of the output from blob2wired
    with open(output, mode="wb") as out:
        while start < app_length:
            # generate mutable byte array for the header
            hdr_binarray = bytearray([0x00] * hdr_length)

            if app_length - start > max_size:
                end = start + max_size
            else:
                end = app_length

            if imagetype == defs.AM_SECBOOT_WIRED_IMAGETYPE_INFO0_NOOTA:
                key = INFO_KEY
                # word offset
                defs.fill_word(
                    hdr_binarray, defs.AM_WU_IMAGEHDR_OFFSET_ADDR, loadaddress >> 2
                )
            else:
                key = FLASH_KEY
                # load address
                defs.fill_word(
                    hdr_binarray, defs.AM_WU_IMAGEHDR_OFFSET_ADDR, loadaddress
                )
            # Create imageType & options
            hdr_binarray[defs.AM_WU_IMAGEHDR_OFFSET_IMAGETYPE] = imagetype
            # Set the options only for the first block
            if start == 0:
                hdr_binarray[defs.AM_WU_IMAGEHDR_OFFSET_OPTIONS] = options_val
            else:
                hdr_binarray[defs.AM_WU_IMAGEHDR_OFFSET_OPTIONS] = 0

            # Create Info0 Update Blob for wired update
            defs.fill_word(hdr_binarray, defs.AM_WU_IMAGEHDR_OFFSET_KEY, key)
            # update size
            defs.fill_word(hdr_binarray, defs.AM_WU_IMAGEHDR_OFFSET_SIZE, end - start)

            w0 = (
                (authalgo & 0xF)
                | ((auth_key_idx << 8) & 0xF00)
                | ((encalgo << 16) & 0xF0000)
                | ((enc_key_idx << 24) & 0x0F000000)
            )

            defs.fill_word(hdr_binarray, 0, w0)

            if encalgo != 0:
                key_idx = enc_key_idx - MIN_AES_KEY_IDX
                iv_val_aes = os.urandom(defs.AM_SECBOOT_AESCBC_BLOCK_SIZE_BYTES)
                defs.am_print("Initialization Vector")
                defs.am_print([hex(n) for n in iv_val_aes])
                key_aes = os.urandom(key_size)
                defs.am_print("AES Key used for encryption")
                defs.am_print([hex(key_aes[n]) for n in range(0, key_size)])
                # Encrypted Part - after security header
                enc_binarray = defs.encrypt_app_aes(
                    (
                        hdr_binarray[defs.AM_WU_IMAGEHDR_START_ENCRYPT : hdr_length]
                        + app_binarray[start:end]
                    ),
                    key_aes,
                    iv_val_aes,
                )
                # Encrypted Key
                enc_key = defs.encrypt_app_aes(
                    key_aes,
                    KEY_TBL_AES[
                        key_idx
                        * defs.AM_SECBOOT_KEYIDX_BYTES : (
                            key_idx * defs.AM_SECBOOT_KEYIDX_BYTES + key_size
                        )
                    ],
                    defs.IV_VAL_0,
                )
                defs.am_print("Encrypted Key")
                defs.am_print([hex(enc_key[n]) for n in range(0, key_size)])
                # Fill up the IV
                for x in range(0, defs.AM_SECBOOT_AESCBC_BLOCK_SIZE_BYTES):
                    hdr_binarray[defs.AM_WU_IMAGEHDR_OFFSET_IV + x] = iv_val_aes[x]
                # Fill up the Encrypted Key
                for x in range(0, key_size):
                    hdr_binarray[defs.AM_WU_IMAGEHDR_OFFSET_KEK + x] = enc_key[x]
            else:
                enc_binarray = (
                    hdr_binarray[defs.AM_WU_IMAGEHDR_START_ENCRYPT : hdr_length]
                    + app_binarray[start:end]
                )

            if authalgo != 0:  # Authentication needed
                key_idx = auth_key_idx - MIN_HMAC_KEY_IDX
                # Initialize the HMAC - Sign is computed on image following the signature
                sig = defs.compute_hmac(
                    KEY_TBL_HMAC[
                        key_idx
                        * defs.AM_SECBOOT_KEYIDX_BYTES : (
                            key_idx * defs.AM_SECBOOT_KEYIDX_BYTES
                            + defs.AM_HMAC_SIG_SIZE
                        )
                    ],
                    hdr_binarray[
                        defs.AM_WU_IMAGEHDR_START_HMAC : defs.AM_WU_IMAGEHDR_START_ENCRYPT
                    ]
                    + enc_binarray,
                )
                defs.am_print("HMAC")
                defs.am_print([hex(n) for n in sig])
                # Fill up the HMAC
                for x in range(0, defs.AM_HMAC_SIG_SIZE):
                    hdr_binarray[defs.AM_WU_IMAGEHDR_OFFSET_SIG + x] = sig[x]

            defs.am_print("Writing to file ", output)
            defs.am_print(
                "Image from ",
                str(hex(start)),
                " to ",
                str(hex(end)),
                " will be loaded at",
                str(hex(loadaddress)),
            )
            out.write(hdr_binarray[0 : defs.AM_WU_IMAGEHDR_START_ENCRYPT])
            out.write(enc_binarray)

            # Reset start for next chunk
            start = end
            loadaddress = loadaddress + max_size


def upload(args):
    """Main function."""
    global load_success
    global load_tries

    # Open a serial port, and communicate with Device
    #
    # Max flashing time depends on the amount of SRAM available.
    # For very large images, the flashing happens page by page.
    # However if the image can fit in the free SRAM, it could take a long time
    # for the whole image to be flashed at the end.
    # The largest image which can be stored depends on the max SRAM.
    # Assuming worst case ~100 ms/page of flashing time, and allowing for the
    # image to be close to occupying full SRAM (256K) which is 128 pages.

    connection_timeout = 5

    print(f"Connecting over serial port {args.port}...", flush=True)

    # Check to see if the com port is available
    try:
        with serial.Serial(args.port, args.baud, timeout=connection_timeout) as ser:
            pass
    except:
        # Show a list of com ports and recommend one
        print("Detected Serial Ports:")
        devices = list_ports.comports()
        for dev in devices:
            print(dev.description)
            # The SparkFun BlackBoard has CH340 in the description
            if "CH340" in dev.description:
                print(
                    "The port you selected was not found. But we did detect a CH340 on "
                    + dev.device
                    + " so you might try again on that port."
                )
                break
            if "FTDI" in dev.description:
                print(
                    "The port you selected was not found. But we did detect an FTDI on "
                    + dev.device
                    + " so you might try again on that port."
                )
                break
            if "USB Serial Device" in dev.description:
                print(
                    "The port you selected was not found. But we did detect a USB Serial Device on "
                    + dev.device
                    + " so you might try again on that port."
                )
                break
        else:
            print("Com Port not found - Did you select the right one?")

        sys.exit()

    # Begin talking over com port

    # The auto-bootload sequence is good but not fullproof. The bootloader
    # fails to correctly catch the BOOT signal about 1 out of ten times.
    # Auto-retry this number of times before we give up.

    while load_tries < 3:
        load_success = False

        with serial.Serial(args.port, args.baud, timeout=connection_timeout) as ser:
            # DTR is driven low when serial port open. DTR has now pulled RST low.

            time.sleep(0.005)  # 3ms and 10ms work well. Not 50, and not 0.

            # Setting RTS/DTR high causes the bootload pin to go high, then fall across 100ms
            ser.setDTR(0)  # Set DTR high
            ser.setRTS(0)  # Set RTS high - support the CH340E

            # Give bootloader a chance to run and check bootload pin before
            # communication begins. But must initiate com before bootloader
            # timeout of 250ms.
            time.sleep(0.100)  # 100ms works well
            # reset the input bufer to discard any UART traffic that the device
            # may have generated
            ser.reset_input_buffer()

            connect_device(ser, args)

            if load_success:
                print("Tries =", load_tries)
                print("Upload complete!")
                sys.exit()
            else:
                print("Fail")

            load_tries = load_tries + 1

    print("Tries =", load_tries)
    print("Upload failed")
    sys.exit()


def connect_device(ser, args):
    """Communicate with Device.

    Given a serial port, connects to the target device using the UART.
    """
    global load_success

    # Send Hello
    # generate mutable byte array for the header
    hello = bytearray([0x00] * 4)
    defs.fill_word(hello, 0, ((8 << 16) | defs.AM_SECBOOT_WIRED_MSGTYPE_HELLO))
    logging.debug("Sending Hello.")
    response = send_command(hello, 88, ser)

    # Check if response failed
    if not response:
        logging.debug("Failed to respond")
        return

    logging.debug("Received response for Hello")
    word = defs.word_from_bytes(response, 4)
    if (word & 0xFFFF) == defs.AM_SECBOOT_WIRED_MSGTYPE_STATUS:
        # Received Status
        print("Bootloader connected")

        logging.debug("Received Status")
        logging.debug("length = %s", hex((word >> 16)))
        logging.debug("version = %s", hex(defs.word_from_bytes(response, 8)))
        logging.debug("Max Storage = %s", hex(defs.word_from_bytes(response, 12)))
        logging.debug("Status = %s", hex(defs.word_from_bytes(response, 16)))
        logging.debug("State = %s", hex(defs.word_from_bytes(response, 20)))
        logging.debug("AMInfo = ")
        for x in range(24, 88, 4):
            logging.debug("\t%s", hex(defs.word_from_bytes(response, x)))

        abort = args.abort
        if abort != -1:
            # Send OTA Desc
            logging.debug("Sending Abort command.")
            abort_msg = bytearray([0x00] * 8)
            defs.fill_word(
                abort_msg, 0, ((12 << 16) | defs.AM_SECBOOT_WIRED_MSGTYPE_ABORT)
            )
            defs.fill_word(abort_msg, 4, abort)
            if not send_ackd_command(abort_msg, ser):
                logging.debug("Failed to ack command")
                return

        otadescaddr = args.otadesc
        if otadescaddr != 0xFFFFFFFF:
            # Send OTA Desc
            logging.debug("Sending OTA Descriptor = %s", hex(otadescaddr))
            ota_desc = bytearray([0x00] * 8)
            defs.fill_word(
                ota_desc, 0, ((12 << 16) | defs.AM_SECBOOT_WIRED_MSGTYPE_OTADESC)
            )
            defs.fill_word(ota_desc, 4, otadescaddr)
            if not send_ackd_command(ota_desc, ser):
                logging.debug("Failed to ack command")
                return

        if uploadbinfile != "":
            # Read the binary file from the command line.
            with open(uploadbinfile, mode="rb") as binfile:
                application = binfile.read()
            # Gather the important binary metadata.
            total_len = len(application)
            # Send Update command
            logging.debug("Sending Update Command.")

            # It is assumed that max_size is 256b multiple
            max_image_size = args.split
            if (max_image_size & (defs.FLASH_PAGE_SIZE - 1)) != 0:
                logging.debug("split needs to be multiple of flash page size")
                return

            # Each Block of image consists of defs.AM_WU_IMAGEHDR_SIZE Bytes Image header and the
            # Image blob
            max_update_size = defs.AM_WU_IMAGEHDR_SIZE + max_image_size
            num_updates = (
                total_len + max_update_size - 1
            ) // max_update_size  # Integer division
            logging.debug("number of updates needed = %s", num_updates)

            end = total_len
            for num_updates in range(num_updates, 0, -1):
                start = (num_updates - 1) * max_update_size
                crc = defs.crc32(application[start:end])
                applen = end - start
                logging.debug(
                    "Sending block of size %s from %s to %s",
                    str(hex(applen)),
                    str(hex(start)),
                    str(hex(end)),
                )
                end = end - applen

                update = bytearray([0x00] * 16)
                defs.fill_word(
                    update, 0, ((20 << 16) | defs.AM_SECBOOT_WIRED_MSGTYPE_UPDATE)
                )
                defs.fill_word(update, 4, applen)
                defs.fill_word(update, 8, crc)
                # Size = 0 => We're not piggybacking any data to IMAGE command
                defs.fill_word(update, 12, 0)

                if not send_ackd_command(update, ser):
                    logging.debug("Failed to ack command")
                    return

                # Loop over the bytes in the image, and send them to the target.
                # Max chunk size is AM_MAX_UART_MSG_SIZE adjusted for the header for Data message
                max_chunk_size = defs.AM_MAX_UART_MSG_SIZE - 12
                for x in range(0, applen, max_chunk_size):
                    # Split the application into chunks of max_chunk_size bytes.
                    # This is the max chunk size supported by the UART bootloader
                    if (x + max_chunk_size) > applen:
                        chunk = application[start + x : start + applen]
                    else:
                        chunk = application[start + x : start + x + max_chunk_size]

                    chunklen = len(chunk)

                    # Build a data packet with a "data command" a "length" and the actual
                    # payload bytes, and send it to the target.
                    data_msg = bytearray([0x00] * 8)
                    defs.fill_word(
                        data_msg,
                        0,
                        (((chunklen + 12) << 16) | defs.AM_SECBOOT_WIRED_MSGTYPE_DATA),
                    )
                    # seqNo
                    defs.fill_word(data_msg, 4, x)

                    logging.debug("Sending Data Packet of length %s", chunklen)
                    if not send_ackd_command(data_msg + chunk, ser):
                        logging.debug("Failed to ack command")
                        return

        if args.raw != "":
            # Read the binary file from the command line.
            with open(args.raw, mode="rb") as rawfile:
                blob = rawfile.read()
            # Send Raw command
            logging.debug("Sending Raw Command.")
            ser.write(blob)

        if args.reset != 0:
            # Send reset
            logging.debug("Sending Reset Command.")
            resetmsg = bytearray([0x00] * 8)
            defs.fill_word(
                resetmsg, 0, ((12 << 16) | defs.AM_SECBOOT_WIRED_MSGTYPE_RESET)
            )
            # options
            defs.fill_word(resetmsg, 4, args.reset)
            if not send_ackd_command(resetmsg, ser):
                logging.debug("Failed to ack command")
                return

        # Success! We're all done
        load_success = True
    else:
        # Received Wrong message
        logging.debug("Received Unknown Message")
        word = defs.word_from_bytes(response, 4)
        logging.debug("msgType = %s", hex(word & 0xFFFF))
        logging.debug("Length = %s", hex(word >> 16))
        logging.debug([hex(n) for n in response])
        # print("!!!Wired Upgrade Unsuccessful!!!....Terminating the script")

        # exit()


def send_ackd_command(command, ser):
    """Send ACK'd command.

    Sends a command, and waits for an ACK.
    """
    response = send_command(command, 20, ser)

    # Check if response failed
    if not response:
        logging.debug("Response not valid")
        return False  # Return error

    word = defs.word_from_bytes(response, 4)
    if (word & 0xFFFF) == defs.AM_SECBOOT_WIRED_MSGTYPE_ACK:
        # Received ACK
        if (
            defs.word_from_bytes(response, 12)
            != defs.AM_SECBOOT_WIRED_ACK_STATUS_SUCCESS
        ):
            logging.debug("Received NACK")
            logging.debug("msgType = %s", hex(defs.word_from_bytes(response, 8)))
            logging.debug("error = %s", hex(defs.word_from_bytes(response, 12)))
            logging.debug("seqNo = %s", hex(defs.word_from_bytes(response, 16)))
            # print("!!!Wired Upgrade Unsuccessful!!!....Terminating the script")
            logging.debug("Upload failed: No ack to command")

            return False  # Return error

    return response


def send_command(params, response_len, ser):
    """Send command.

    Sends a command, and waits for the response.
    """
    # Compute crc
    crc = defs.crc32(params)
    #    print([hex(n) for n in defs.int_to_bytes(crc)])
    #    print([hex(n) for n in params])
    # send crc first
    ser.write(defs.int_to_bytes(crc))

    # Next, send the parameters.
    ser.write(params)

    response = ""
    response = ser.read(response_len)

    # Make sure we got the number of bytes we asked for.
    if len(response) != response_len:
        logging.debug(
            "No response for command %s",
            "0x{defs.word_from_bytes(params, 0) & 0xFFFF:08X}",
        )
        n = len(response)
        if n != 0:
            logging.debug("received bytes %s", len(response))
            logging.debug([hex(n) for n in response])
        return False

    return response


def send_bytewise_command(command, params, response_len, ser):
    """Send a command that uses an array of bytes as its parameters."""
    # Send the command first.
    ser.write(defs.int_to_bytes(command))

    # Next, send the parameters.
    ser.write(params)

    response = ""
    response = ser.read(response_len)

    # Make sure we got the number of bytes we asked for.
    if len(response) != response_len:
        print("Upload failed: No reponse to command")
        logging.debug("No response for command %s", f"0x{command:08x}")
        sys.exit()

    return response


def parse_arguments():
    """Parse CLI arguments."""
    parser = argparse.ArgumentParser(
        description="Combination script to upload application binaries to Artemis module. "
        "Includes:\n"
        "\t'- bin2blob: create OTA blob from binary image'\n"
        "\t'- blob2wired: create wired update image from OTA blob'\n"
        "\t'- upload: send wired update image to Apollo3 Artemis module via serial port'\n\n"
        "There are many command-line arguments."
        "They have been labeled by which steps they apply to\n"
    )

    parser.add_argument(
        "-a",
        dest="abort",
        default=-1,
        type=int,
        choices=[0, 1, -1],
        help="upload: Should it send abort command? "
        "(0 = abort, 1 = abort and quit, -1 = no abort) (default is -1)",
    )

    parser.add_argument(
        "--authalgo",
        dest="authalgo",
        type=defs.auto_int,
        default=0,
        choices=range(0, defs.AM_SECBOOT_AUTH_ALGO_MAX + 1),
        help="bin2blob, blob2wired: " + str(defs.HELP_AUTH_ALGO),
    )

    parser.add_argument(
        "--auth_i",
        dest="auth_i",
        type=defs.auto_int,
        default=0,
        choices=[0, 1],
        help="bin2blob: Install Authentication check enabled (Default = N)?",
    )

    parser.add_argument(
        "--auth_b",
        dest="auth_b",
        type=defs.auto_int,
        default=0,
        choices=[0, 1],
        help="bin2blob: Boot Authentication check enabled (Default = N)?",
    )

    parser.add_argument(
        "--authkey",
        dest="authkey",
        type=defs.auto_int,
        default=(MIN_HMAC_KEY_IDX),
        choices=range(MIN_HMAC_KEY_IDX, MAX_HMAC_KEY_IDX + 1),
        help="bin2blob, blob2wired: Authentication Key Idx? ("
        + str(MIN_HMAC_KEY_IDX)
        + " to "
        + str(MAX_HMAC_KEY_IDX)
        + ")",
    )

    parser.add_argument(
        "-b",
        dest="baud",
        default=115200,
        type=int,
        help="upload: Baud Rate (default is 115200)",
    )

    parser.add_argument(
        "--bin",
        dest="app_file",
        type=argparse.FileType("rb"),
        help="bin2blob: binary file (blah.bin)",
    )

    parser.add_argument(
        "-clean",
        dest="clean",
        default=0,
        type=int,
        help="All: whether or not to remove intermediate files",
    )

    parser.add_argument(
        "--child0",
        dest="child0",
        type=defs.auto_int,
        default=hex(0xFFFFFFFF),
        help="bin2blob: child (blobPtr#0 for Main / feature key for AM3P)",
    )

    parser.add_argument(
        "--child1",
        dest="child1",
        type=defs.auto_int,
        default=hex(0xFFFFFFFF),
        help="bin2blob: child (blobPtr#1 for Main)",
    )

    parser.add_argument(
        "--crc_i",
        dest="crc_i",
        type=defs.auto_int,
        default=1,
        choices=[0, 1],
        help="bin2blob: Install CRC check enabled (Default = Y)?",
    )

    parser.add_argument(
        "--crc_b",
        dest="crc_b",
        type=defs.auto_int,
        default=0,
        choices=[0, 1],
        help="bin2blob: Boot CRC check enabled (Default = N)?",
    )

    parser.add_argument(
        "--encalgo",
        dest="encalgo",
        type=defs.auto_int,
        default=0,
        choices=range(0, defs.AM_SECBOOT_ENC_ALGO_MAX + 1),
        help="bin2blob, blob2wired: " + str(defs.HELP_ENC_ALGO),
    )

    parser.add_argument(
        "--erase_prev",
        dest="erase_prev",
        type=defs.auto_int,
        default=0,
        choices=[0, 1],
        help="bin2blob: erase_prev (Valid only for main)",
    )

    # parser.add_argument('-f', dest='binfile', default='',
    #                     help = 'upload: Binary file to program into the target device')

    parser.add_argument(
        "-i",
        dest="imagetype",
        default=defs.AM_SECBOOT_WIRED_IMAGETYPE_INVALID,
        type=defs.auto_int,
        choices=[
            (defs.AM_SECBOOT_WIRED_IMAGETYPE_SBL),
            (defs.AM_SECBOOT_WIRED_IMAGETYPE_AM3P),
            (defs.AM_SECBOOT_WIRED_IMAGETYPE_PATCH),
            (defs.AM_SECBOOT_WIRED_IMAGETYPE_MAIN),
            (defs.AM_SECBOOT_WIRED_IMAGETYPE_CHILD),
            (defs.AM_SECBOOT_WIRED_IMAGETYPE_CUSTPATCH),
            (defs.AM_SECBOOT_WIRED_IMAGETYPE_NONSECURE),
            (defs.AM_SECBOOT_WIRED_IMAGETYPE_INFO0),
            (defs.AM_SECBOOT_WIRED_IMAGETYPE_INFO0_NOOTA),
            (defs.AM_SECBOOT_WIRED_IMAGETYPE_INVALID),
        ],
        help="blob2wired, upload: ImageType ("
        + str(defs.AM_SECBOOT_WIRED_IMAGETYPE_SBL)
        + ": SBL, "
        + str(defs.AM_SECBOOT_WIRED_IMAGETYPE_AM3P)
        + ": AM3P, "
        + str(defs.AM_SECBOOT_WIRED_IMAGETYPE_PATCH)
        + ": Patch, "
        + str(defs.AM_SECBOOT_WIRED_IMAGETYPE_MAIN)
        + ": Main, "
        + str(defs.AM_SECBOOT_WIRED_IMAGETYPE_CHILD)
        + ": Child, "
        + str(defs.AM_SECBOOT_WIRED_IMAGETYPE_CUSTPATCH)
        + ": CustOTA, "
        + str(defs.AM_SECBOOT_WIRED_IMAGETYPE_NONSECURE)
        + ": NonSecure, "
        + str(defs.AM_SECBOOT_WIRED_IMAGETYPE_INFO0)
        + ": Info0 "
        + str(defs.AM_SECBOOT_WIRED_IMAGETYPE_INFO0_NOOTA)
        + ": Info0_NOOTA) "
        + str(defs.AM_SECBOOT_WIRED_IMAGETYPE_INVALID)
        + ": Invalid) "
        "- default[Invalid]",
    )

    parser.add_argument(
        "--kek",
        dest="kek",
        type=defs.auto_int,
        default=(MIN_AES_KEY_IDX),
        choices=range(MIN_AES_KEY_IDX, MAX_AES_KEY_IDX + 1),
        help="KEK index? ("
        + str(MIN_AES_KEY_IDX)
        + " to "
        + str(MAX_AES_KEY_IDX)
        + ")",
    )

    parser.add_argument(
        "--load-address-wired",
        dest="loadaddress_blob",
        type=defs.auto_int,
        default=hex(0x60000),
        help="blob2wired: Load address of the binary"
        " - Where in flash the blob will be stored"
        " (could be different than install address of binary within).",
    )

    parser.add_argument(
        "--load-address-blob",
        dest="loadaddress_image",
        type=defs.auto_int,
        default=hex(defs.AM_SECBOOT_DEFAULT_NONSECURE_MAIN),
        help="bin2blob: Load address of the binary.",
    )

    parser.add_argument(
        "--loglevel",
        dest="loglevel",
        type=defs.auto_int,
        default=defs.AM_PRINT_LEVEL_INFO,
        choices=range(defs.AM_PRINT_LEVEL_MIN, defs.AM_PRINT_LEVEL_MAX + 1),
        help="bin2blob, blob2wired: " + str(defs.HELP_PRINT_LEVEL),
    )

    parser.add_argument(
        "--magic-num",
        dest="magic_num",
        default=hex(defs.AM_IMAGE_MAGIC_NONSECURE),
        type=lambda x: x.lower(),
        #                        type = str.lower,
        choices=[
            hex(defs.AM_IMAGE_MAGIC_MAIN),
            hex(defs.AM_IMAGE_MAGIC_CHILD),
            hex(defs.AM_IMAGE_MAGIC_CUSTPATCH),
            hex(defs.AM_IMAGE_MAGIC_NONSECURE),
            hex(defs.AM_IMAGE_MAGIC_INFO0),
        ],
        help="bin2blob: Magic Num ("
        + str(hex(defs.AM_IMAGE_MAGIC_MAIN))
        + ": Main, "
        + str(hex(defs.AM_IMAGE_MAGIC_CHILD))
        + ": Child, "
        + str(hex(defs.AM_IMAGE_MAGIC_CUSTPATCH))
        + ": CustOTA, "
        + str(hex(defs.AM_IMAGE_MAGIC_NONSECURE))
        + ": NonSecure, "
        + str(hex(defs.AM_IMAGE_MAGIC_INFO0))
        + ": Info0) "
        "- default[Main]",
    )

    parser.add_argument(
        "-o",
        dest="output",
        default="wuimage",
        help="all: Output filename (without the extension) [also used for intermediate filenames]",
    )

    parser.add_argument(
        "-ota",
        dest="otadesc",
        type=defs.auto_int,
        default=0xFE000,
        help="upload: OTA Descriptor Page address (hex)"
        " - (Default is 0xFE000 - at the end of main flash)"
        "- enter 0xFFFFFFFF to instruct SBL to skip OTA",
    )

    parser.add_argument(
        "--options",
        dest="options",
        type=defs.auto_int,
        default=0x1,
        help="blob2wired: Options (16b hex value) "
        "- bit0 instructs to perform OTA of the image after wired download "
        "(set to 0 if only downloading & skipping OTA flow)",
    )

    parser.add_argument(
        "-p",
        dest="protection",
        type=defs.auto_int,
        default=0,
        choices=[0x0, 0x1, 0x2, 0x3],
        help="bin2blob: protection info 2 bit C W",
    )

    parser.add_argument("-port", dest="port", help="upload: Serial COMx Port")

    parser.add_argument(
        "-r",
        dest="reset",
        default=1,
        type=defs.auto_int,
        choices=[0, 1, 2],
        help="upload: Should it send reset command after image download? "
        "(0 = no reset, 1 = POI, 2 = POR) (default is 1)",
    )

    parser.add_argument(
        "--raw", dest="raw", default="", help="upload: Binary file for raw message"
    )

    parser.add_argument(
        "--split",
        dest="split",
        type=defs.auto_int,
        default=hex(defs.MAX_DOWNLOAD_SIZE),
        help="blob2wired, upload: "
        "Specify the max block size if the image will be downloaded in pieces",
    )

    parser.add_argument(
        "--version",
        dest="version",
        type=defs.auto_int,
        default=0,
        help="bin2blob: version (15 bit)",
    )

    parser.add_argument(
        "-v",
        "--verbose",
        default=0,
        help="All: Enable verbose output",
        action="store_true",
    )

    args = parser.parse_args()
    args.magic_num = int(args.magic_num, 16)

    return args


# ******************************************************************************
#
# Main function.
#
# ******************************************************************************

# example calling:
# python artemis_bin_to_board.py --bin application.bin --load-address-blob 0x20000 --magic-num 0xCB
#   -o application --version 0x0 --load-address-wired 0xC000 -i 6 --options 0x1 -b 921600 -port COM4
#   -r 1 -v


def main():
    """Main function."""
    # Read the arguments.
    args = parse_arguments()
    defs.am_set_print_level(args.loglevel)

    bin2blob_process(
        args.loadaddress_blob,
        args.app_file,
        args.magic_num,
        args.crc_i,
        args.crc_b,
        args.auth_i,
        args.auth_b,
        args.protection,
        args.authkey,
        args.output,
        args.kek,
        args.version,
        args.erase_prev,
        args.child0,
        args.child1,
        args.authalgo,
        args.encalgo,
    )
    blob2wired_process(
        blob2wiredfile,
        args.imagetype,
        args.loadaddress_image,
        args.authalgo,
        args.encalgo,
        args.authkey,
        args.kek,
        args.options,
        args.split,
        args.output,
    )

    # todo: link the bin2blob step with the blob2wired step by input/output files

    if args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)

    upload(args)

    if args.clean == 1:
        print(
            "Cleaning up intermediate files"
        )  # todo: why isnt this showing w/ -clean option?


if __name__ == "__main__":
    main()

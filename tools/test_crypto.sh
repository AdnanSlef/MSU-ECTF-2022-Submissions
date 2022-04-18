#!/bin/bash

echo '
--sysname=crypto-test-1
--oldest-allowed-version=1
--sock-root=socks
--uart-sock=1558
--fw-root=firmware
--raw-fw-file=example_fw.bin
--protected-fw-file=test_crypto_1_fw.prot
--fw-version=2
--fw-message=Congratulations! The bootloader is booting the example images!
--cfg-root=configuration
--raw-cfg-file=example_cfg.bin
--protected-cfg-file=test_crypto_1_cfg.prot
--rb-len=100
--boot-msg-file=test_crypto_1_boot.txt
--emulated
' > test_crypto_1.cfg

cmd () {
    python3 tools/run_saffire.py $1 @test_crypto_1.cfg
}

go () {
    cmd build-system
    cmd load-device
    cmd launch-bootloader

    cmd fw-protect
    cmd cfg-protect

    cmd fw-update
    cmd cfg-load

    cmd fw-readback
    cmd cfg-readback

    cmd boot
    cmd monitor
}

end () {
    cmd kill-system
}

"$@"
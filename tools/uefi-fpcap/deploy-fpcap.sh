#!/usr/bin/env bash
# Deploy fpcap.efi to the ESP and arm it as a ONE-SHOT next boot. Run as root on the laptop.
# Reversible: `efibootmgr -b <NUM> -B` removes the entry; `efibootmgr -N` clears BootNext.
set -euo pipefail

efi="${1:-$HOME/src/uefi-fpcap/fpcap.efi}"
disk=/dev/nvme0n1
part=1

[ -f "$efi" ] || { echo "missing $efi (run: make -C ~/src/uefi-fpcap)"; exit 1; }

mkdir -p /boot/efi/EFI/fpcap
cp "$efi" /boot/efi/EFI/fpcap/fpcap.efi
echo "copied fpcap.efi to the ESP"

# Create the boot entry only if it isn't already there.
num=$(efibootmgr | sed -n 's/^Boot\([0-9A-F]\{4\}\)\*\? fpcap$/\1/p' | head -1)
if [ -z "$num" ]; then
  efibootmgr -c -d "$disk" -p "$part" -L "fpcap" -l '\EFI\fpcap\fpcap.efi' >/dev/null
  num=$(efibootmgr | sed -n 's/^Boot\([0-9A-F]\{4\}\)\*\? fpcap$/\1/p' | head -1)
  echo "created boot entry Boot$num (fpcap)"
else
  echo "boot entry Boot$num (fpcap) already exists"
fi

efibootmgr -n "$num" >/dev/null
echo "armed: next boot runs fpcap once (BootNext=$num), then reverts."
echo
echo "Now power the laptop OFF completely, then power it ON by resting a finger"
echo "on the power/fingerprint button. fpcap runs, scans, and prints a KEY= line"
echo "if the key was staged. Press a key to continue booting back to Linux."
echo "Dumps are saved to /boot/efi/fpcap-*.bin for offline scanning."

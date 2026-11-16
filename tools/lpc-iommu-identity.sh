#!/usr/bin/env bash
# Put the IOMMU group of the LPC/eSPI bridge (00:1f.0) into identity (pass-through) mode at runtime.
#
# Why: on GXFP51B7 machines the EC reads the mailbox window (host RAM at FPDA) by
# eSPI bus mastering through 00:1f.0. With VT-d DMA remapping on and no RMRR for
# that range, every read faults ("DMAR: ... fault addr 0x40200000 ... PTE Read
# access is not set") and the MCU never sees a command.
#
# The group's other functions (audio, SMBus, SPI flash) must be unbound while the
# type changes; they are rebound afterwards. Run as root.
set -euo pipefail

bridge=0000:00:1f.0
grp_dir=$(readlink -f "/sys/bus/pci/devices/$bridge/iommu_group")
echo "group $(basename "$grp_dir"): $(cat "$grp_dir/type")"
[ "$(cat "$grp_dir/type")" = identity ] && exit 0

declare -A bound=()
for dev in "$grp_dir"/devices/*; do
  bdf=$(basename "$dev")
  if [ -e "$dev/driver" ]; then
    bound[$bdf]=$(basename "$(readlink "$dev/driver")")
    echo "$bdf" > "$dev/driver/unbind"
    echo "unbound $bdf (${bound[$bdf]})"
  fi
done

rc=0
echo identity > "$grp_dir/type" || rc=$?

for bdf in "${!bound[@]}"; do
  echo "$bdf" > "/sys/bus/pci/drivers/${bound[$bdf]}/bind" && echo "rebound $bdf (${bound[$bdf]})"
done

echo "group $(basename "$grp_dir"): $(cat "$grp_dir/type")"
exit "$rc"

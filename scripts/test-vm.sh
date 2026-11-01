#!/usr/bin/env bash
# Create a disposable Ubuntu 24.04 KVM test VM ("signal-test") with a "clean" snapshot.
# Run as your normal user (not root) from anywhere; it calls sudo where needed.
# The VM is host-wide (qemu:///system); reset before tests with:
#   virsh -c qemu:///system snapshot-revert signal-test clean --running && scripts/test-vm.sh wait-ready
set -euo pipefail

VM=signal-test
MEM=4096
CPUS=2
DISK=20G
DIR=/var/lib/libvirt/images
BASE=noble-server-cloudimg-amd64.img
URL=https://cloud-images.ubuntu.com/noble/current
PUBKEY=${PUBKEY:-$HOME/.ssh/id_rsa.pub}
# Member of libvirt in /etc/group but this session predates it: re-exec with the group (no relogin).
if ! id -nG | grep -qw libvirt && id -nG "$USER" | grep -qw libvirt && [[ -z ${TEST_VM_SG:-} ]]; then
  exec env TEST_VM_SG=1 sg libvirt -c "$(printf '%q ' "$0" "$@")"
fi
if id -nG | grep -qw libvirt; then VIRSH="virsh -c qemu:///system"; else VIRSH="sudo virsh -c qemu:///system"; fi
SSH_OPTS="-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null -o LogLevel=ERROR -o ConnectTimeout=5 -o BatchMode=yes"

# Bounded guest readiness check (usage: test-vm.sh wait-ready [timeout_s], default 60).
# Waits for the VM's IP, SSH, and a stable owner of org.freedesktop.systemd1 on the user bus
# (same owner on two reads 1s apart). Reads only, but the first bus call can socket-activate
# the session bus if it is not already up. Exit 0 = ready, 1 = not ready within the timeout.
wait_ready() {
  local timeout=${1:-60} deadline ip=
  deadline=$((SECONDS + timeout))
  local state
  state=$($VIRSH domstate "$VM" 2>&1) || { echo "not ready: libvirt query failed: $state" >&2
    echo "  (not in the libvirt group yet? log out and back in, or run: newgrp libvirt)" >&2; return 1; }
  [[ $state == running ]] || { echo "not ready: $VM is '$state'" >&2; return 1; }
  until ip=$($VIRSH domifaddr "$VM" 2>/dev/null | awk '/ipv4/{sub(/\/.*/,"",$4); print $4; exit}') && [[ -n $ip ]]; do
    ((SECONDS < deadline)) || { echo "not ready: no IP for $VM" >&2; return 1; }; sleep 1
  done
  until ssh $SSH_OPTS "$USER@$ip" true 2>/dev/null; do
    ((SECONDS < deadline)) || { echo "not ready: no SSH to $ip" >&2; return 1; }; sleep 1
  done
  # shellcheck disable=SC2029  # remaining time is expanded locally on purpose
  ssh $SSH_OPTS "$USER@$ip" "remaining=$((deadline - SECONDS)); "'
    q() { busctl --user call org.freedesktop.DBus /org/freedesktop/DBus org.freedesktop.DBus \
            GetNameOwner s org.freedesktop.systemd1 2>/dev/null; }
    end=$((SECONDS + remaining))
    while ((SECONDS < end)); do
      a=$(q) && sleep 1 && b=$(q) && [[ -n $a && $a == "$b" ]] && { a=${a#s }; echo "ready: systemd1 owner ${a//\"/}"; exit 0; }
      sleep 1
    done
    echo "not ready: org.freedesktop.systemd1 has no stable owner on the user bus" >&2; exit 1'
}
if [[ ${1:-} == wait-ready ]]; then wait_ready "${2:-60}"; exit; fi

# 1. KVM must be available
if [[ ! -e /dev/kvm ]]; then
  sudo modprobe kvm_intel 2>/dev/null || true
  [[ -e /dev/kvm ]] || { echo "No /dev/kvm: VT-x still disabled in BIOS (check: sudo dmesg | grep -i vmx)"; exit 1; }
fi

# 2. Packages + groups
sudo apt-get update
sudo apt-get install -y --no-install-recommends qemu-system-x86 qemu-utils libvirt-daemon-system virtinst
sudo usermod -aG libvirt,kvm "$USER"
sudo systemctl enable --now libvirtd
$VIRSH net-start default 2>/dev/null || true
$VIRSH net-autostart default

# 3. Base cloud image (verified) + thin overlay disk
cd "$DIR"
if [[ ! -f $BASE ]]; then
  sudo wget -q --show-progress "$URL/$BASE"
  curl -fsSL "$URL/SHA256SUMS" | grep " \*\?$BASE\$" | sudo sha256sum -c -
fi
$VIRSH dominfo "$VM" &>/dev/null && { echo "VM '$VM' already exists; remove with: $VIRSH undefine $VM --snapshots-metadata --remove-all-storage"; exit 1; }
sudo qemu-img create -f qcow2 -F qcow2 -b "$DIR/$BASE" "$DIR/$VM.qcow2" "$DISK"

# 4. cloud-init: user = $USER, your SSH key, passwordless sudo
UD=$(mktemp)
cat >"$UD" <<EOF
#cloud-config
hostname: $VM
users:
  - name: $USER
    shell: /bin/bash
    sudo: ALL=(ALL) NOPASSWD:ALL
    ssh_authorized_keys:
      - $(cat "$PUBKEY")
EOF

sudo virt-install --name "$VM" --memory "$MEM" --vcpus "$CPUS" --cpu host-passthrough \
  --import --disk "$DIR/$VM.qcow2",bus=virtio --os-variant ubuntu24.04 \
  --network network=default,model=virtio --graphics none --noautoconsole \
  --cloud-init user-data="$UD"
rm -f "$UD"

# 5. Wait for boot + cloud-init, then snapshot the clean state (offline = consistent)
echo -n "Waiting for IP"
until IP=$($VIRSH domifaddr "$VM" | awk '/ipv4/{sub(/\/.*/,"",$4); print $4; exit}') && [[ -n $IP ]]; do echo -n .; sleep 2; done
echo " $IP"
SSH="ssh $SSH_OPTS $USER@$IP"
until $SSH true 2>/dev/null; do sleep 2; done
$SSH 'cloud-init status --wait >/dev/null; sudo cloud-init clean --logs >/dev/null; sudo touch /etc/cloud/cloud-init.disabled'
# Ready user manager + session bus at boot: otherwise the first bus client socket-activates
# dbus and races systemd --user acquiring org.freedesktop.systemd1 (NameHasNoOwner).
$SSH 'sudo loginctl enable-linger "$USER" && systemctl --user add-wants default.target dbus.service'
$VIRSH shutdown "$VM"
while [[ $($VIRSH domstate "$VM") != "shut off" ]]; do sleep 1; done
$VIRSH snapshot-create-as "$VM" clean
$VIRSH start "$VM"
wait_ready 120

cat <<EOF

Done. VM '$VM' is running; snapshot 'clean' taken.
  ssh $USER@$IP
  Reset to clean:  virsh -c qemu:///system snapshot-revert $VM clean --running
  Wait until ready: $0 wait-ready [timeout_s]   (run after each revert, before tests)
  Stop / start:    virsh -c qemu:///system shutdown|start $VM
(After re-login, the libvirt group lets you drop sudo; add
 export LIBVIRT_DEFAULT_URI=qemu:///system  to ~/.bashrc to drop -c.)
EOF

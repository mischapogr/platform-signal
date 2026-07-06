#!/usr/bin/env python3
"""Install checksum-verified, pinned Linux Helm/kind/kubectl into a caller-owned directory."""

import argparse
import hashlib
import io
import os
from pathlib import Path
import platform
import tarfile
import tempfile
import time
import urllib.request

HELM_VERSION = "3.19.0"
KIND_VERSION = "0.30.0"
KUBECTL_VERSION = "1.34.0"
# Independently fetched from official versioned release checksum endpoints.
CHECKSUMS = {
    "amd64": {
        "helm": "a7f81ce08007091b86d8bd696eb4d86b8d0f2e1b9f6c714be62f82f96a594496",
        "kind": "517ab7fc89ddeed5fa65abf71530d90648d9638ef0c4cde22c2c11f8097b8889",
        "kubectl": "cfda68cba5848bc3b6c6135ae2f20ba2c78de20059f68789c090166d6abc3e2c",
    },
    "arm64": {
        "helm": "440cf7add0aee27ebc93fada965523c1dc2e0ab340d4348da2215737fc0d76ad",
        "kind": "7ea2de9d2d190022ed4a8a4e3ac0636c8a455e460b9a13ccf19f15d07f4f00eb",
        "kubectl": "00b182d103a8a73da7a4d11e7526d0543dcf352f06cc63a1fde25ce9243f49a0",
    },
}
MAX_DOWNLOAD = 64 * 1024 * 1024
DOWNLOAD_TIMEOUT = 120


def download(url, maximum=MAX_DOWNLOAD):
    deadline = time.monotonic() + DOWNLOAD_TIMEOUT
    with urllib.request.urlopen(url, timeout=20) as response:
        data = bytearray()
        while True:
            if time.monotonic() > deadline:
                raise RuntimeError("download deadline exceeded")
            block = response.read(min(65536, maximum + 1 - len(data)))
            if not block:
                return bytes(data)
            data.extend(block)
            if len(data) > maximum:
                raise RuntimeError("download exceeds byte limit")


def verified(url, expected, suffix=".sha256sum"):
    checksum = download(url + suffix, 4096).decode().split()[0]
    if len(checksum) != 64 or any(c not in "0123456789abcdef" for c in checksum):
        raise RuntimeError("invalid official SHA256 checksum")
    if checksum != expected:
        raise RuntimeError("official release checksum differs from repository pin")
    data = download(url)
    if hashlib.sha256(data).hexdigest() != expected:
        raise RuntimeError("official SHA256 checksum mismatch")
    return data, checksum


def write_executable(directory, name, data):
    # No tar extraction, global PATH change, package installation or shell download.
    with tempfile.NamedTemporaryFile(dir=directory, prefix=name + ".", delete=False) as file:
        temporary = Path(file.name)
        try:
            file.write(data)
            file.flush()
            os.fchmod(file.fileno(), 0o755)
            os.replace(temporary, directory / name)
        finally:
            temporary.unlink(missing_ok=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, default=Path("target/kubernetes-tools"))
    args = parser.parse_args()
    if platform.system() != "Linux":
        raise RuntimeError("installer supports Linux only")
    architecture = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    if architecture is None:
        raise RuntimeError("installer supports Linux AMD64/ARM64 only")
    directory = args.directory.resolve()
    directory.mkdir(parents=True, exist_ok=True)
    helm_url = f"https://get.helm.sh/helm-v{HELM_VERSION}-linux-{architecture}.tar.gz"
    archive, helm_checksum = verified(helm_url, CHECKSUMS[architecture]["helm"])
    with tarfile.open(fileobj=io.BytesIO(archive), mode="r:gz") as tar:
        member = tar.getmember(f"linux-{architecture}/helm")
        if not member.isfile() or member.size > MAX_DOWNLOAD:
            raise RuntimeError("invalid Helm executable archive member")
        extracted = tar.extractfile(member)
        if extracted is None:
            raise RuntimeError("missing Helm executable archive member")
        helm = extracted.read(MAX_DOWNLOAD + 1)
        if len(helm) > MAX_DOWNLOAD:
            raise RuntimeError("Helm executable exceeds byte limit")
    kind_url = f"https://github.com/kubernetes-sigs/kind/releases/download/v{KIND_VERSION}/kind-linux-{architecture}"
    kind, kind_checksum = verified(kind_url, CHECKSUMS[architecture]["kind"])
    kubectl_url = f"https://dl.k8s.io/release/v{KUBECTL_VERSION}/bin/linux/{architecture}/kubectl"
    kubectl, kubectl_checksum = verified(kubectl_url, CHECKSUMS[architecture]["kubectl"], ".sha256")
    write_executable(directory, "helm", helm)
    write_executable(directory, "kind", kind)
    write_executable(directory, "kubectl", kubectl)
    print(f"helm {HELM_VERSION} archive SHA256 {helm_checksum}")
    print(f"kind {KIND_VERSION} binary SHA256 {kind_checksum}")
    print(f"kubectl {KUBECTL_VERSION} binary SHA256 {kubectl_checksum}")
    print(f"Installed Linux {architecture} tools in {directory}")


if __name__ == "__main__":
    main()

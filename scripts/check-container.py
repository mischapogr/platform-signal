#!/usr/bin/env python3
"""Qualify an existing native image, without builds, pulls or publication.

Reuses the Compose durability/auth gate with an exclusively owned project and
bounded resources. --expect-architecture prevents emulation from being reported
as native runtime proof. Temporary overrides and Docker resources are removed.
"""

import argparse
import importlib.util
import json
from pathlib import Path
import platform
import subprocess
import sys
import tempfile

spec = importlib.util.spec_from_file_location("compose_gate", Path(__file__).with_name("check-compose.py"))
compose_gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(compose_gate)


class ContainerGate(compose_gate.Gate):
    def __init__(self, image, architecture, override):
        super().__init__()
        self.image = image
        self.architecture = architecture
        self.override = override

    def compose(self, *args):
        return self.run(["docker", "compose", "--env-file", "/dev/null",
                         "-f", str(compose_gate.ROOT / "docker-compose.yml"),
                         "-f", str(self.override), "-p", self.project, *args])

    def inspect(self):
        container = self.compose("ps", "-q", "signal")
        fields = '{"user":{{json .Config.User}},"readonly":{{json .HostConfig.ReadonlyRootfs}},"caps":{{json .HostConfig.CapDrop}},"security":{{json .HostConfig.SecurityOpt}},"memory":{{json .HostConfig.Memory}},"cpus":{{json .HostConfig.NanoCpus}},"pids":{{json .HostConfig.PidsLimit}},"mounts":{{json .Mounts}},"image":{{json .Image}}}'
        info = json.loads(self.run(["docker", "inspect", "--format", fields, container]))
        require = compose_gate.require
        require(info["user"] == "65532:65532", "non-root container user")
        require(info["readonly"], "read-only root filesystem")
        require("ALL" in info["caps"], "dropped capabilities")
        require(any(item.startswith("no-new-privileges") for item in info["security"]),
                "no-new-privileges")
        require(info["memory"] == 1073741824, "1 GiB memory bound")
        require(info["cpus"] == 2000000000, "2 CPU bound")
        require(info["pids"] == 128, "128 PID bound")
        mounts = {item["Destination"]: item for item in info["mounts"]}
        for destination, writable in [("/var/lib/signal", True),
                                      ("/etc/signal/server.yaml", False),
                                      ("/etc/signal/rules", False)]:
            require(mounts[destination]["RW"] is writable, destination + " mount access")
        require(mounts["/var/lib/signal"]["Name"] == self.project + "_signal-data",
                "exclusively owned persistent volume")
        fields = '{"id":{{json .Id}},"os":{{json .Os}},"architecture":{{json .Architecture}}}'
        image = json.loads(self.run(["docker", "image", "inspect", "--format", fields, info["image"]]))
        require(image["os"] == "linux", "Linux image")
        require(image["architecture"] == self.architecture, "expected native image architecture")
        self.poll(lambda: self.run(["docker", "inspect", "--format", "{{.State.Health.Status}}",
                                   container]) == "healthy", "Docker image healthcheck")
        for binary in ("signal-server", "signal-agent"):
            require(self.run(["docker", "exec", container, binary, "--version"]).startswith(binary + " "),
                    binary + " executable version")
        return {"image": image, "native_architecture": self.architecture,
                "user": info["user"], "readonly_rootfs": info["readonly"],
                "cap_drop": info["caps"], "memory_bytes": info["memory"],
                "cpu_limit": 2, "pids_limit": info["pids"], "healthcheck": "healthy",
                "agent_binary": "version smoke only"}


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--image", default="platform-signal:phase8")
    parser.add_argument("--expect-architecture", choices=("amd64", "arm64"), required=True)
    args = parser.parse_args()
    machine = {"x86_64": "amd64", "aarch64": "arm64"}.get(platform.machine())
    compose_gate.require(machine == args.expect_architecture, "host must run the requested architecture natively")
    with tempfile.TemporaryDirectory(prefix="signal-container-gate-") as directory:
        override = Path(directory) / "override.json"
        override.write_text(json.dumps({"services": {"signal": {
            "image": args.image, "mem_limit": "1g", "cpus": 2.0, "pids_limit": 128,
        }}}))
        gate = ContainerGate(args.image, args.expect_architecture, override)
        # Verify the daemon as well as the Python host; remote Docker is otherwise
        # capable of hiding an emulated execution behind a native client.
        daemon = gate.run(["docker", "info", "--format", "{{.Architecture}}"])
        compose_gate.require({"x86_64": "amd64", "aarch64": "arm64", "amd64": "amd64", "arm64": "arm64"}.get(daemon)
                             == args.expect_architecture, "Docker daemon must run the requested architecture natively")
        try:
            result = gate.execute()
        finally:
            gate.compose("down", "--volumes", "--remove-orphans")
        print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except (RuntimeError, OSError, ValueError, subprocess.TimeoutExpired) as error:
        print("Container gate failed: " + str(error), file=sys.stderr)
        sys.exit(1)

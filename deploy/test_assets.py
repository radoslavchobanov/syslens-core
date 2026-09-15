#!/usr/bin/env python3
"""Offline deployment checks: Python 3.11+, no Docker daemon or dependencies.

Compose accepts JSON as a YAML subset. Keeping these templates in that subset
lets CI parse them strictly without installing a YAML package or fetching a
schema. These checks enforce our deployment contract, not the entire Compose
specification; also run `docker compose config --quiet` on the deployment host.
"""

import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import subprocess
import tempfile
import tomllib
import unittest


ROOT = Path(__file__).resolve().parent


def read(relative):
    return (ROOT / relative).read_text()


def unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError(f"duplicate key: {key}")
        result[key] = value
    return result


def compose(project):
    return json.loads(read(f"{project}/compose.yaml"), object_pairs_hook=unique_object)


def environment(project):
    return dict(
        line.split("=", 1)
        for line in read(f"{project}/.env.example").splitlines()
        if line and not line.startswith("#")
    )


class DeploymentAssets(unittest.TestCase):
    def test_compose_schema_and_isolation(self):
        for project, service in [("gateway", "gateway"), ("ollama", "ollama")]:
            with self.subTest(project=project):
                document = compose(project)
                self.assertEqual(set(document), {"name", "services"})
                self.assertEqual(set(document["services"]), {service})
                definition = document["services"][service]
                self.assertIn(":?", definition["image"], "image selection must be explicit")
                for unsafe in (
                    "privileged", "devices", "device_cgroup_rules", "gpus",
                    "network_mode", "pid", "ipc", "cap_add", "volumes_from",
                    "use_api_socket", "develop", "build",
                ):
                    self.assertNotIn(unsafe, definition)
                self.assertEqual(definition["cap_drop"], ["ALL"])
                self.assertEqual(definition["security_opt"], ["no-new-privileges:true"])
                self.assertEqual(definition["restart"], "unless-stopped")
                self.assertGreater(definition["pids_limit"], 0)
                health = definition["healthcheck"]
                self.assertEqual(health["test"][0], "CMD")
                self.assertGreater(health["retries"], 0)
                for field in ("interval", "timeout", "start_period"):
                    self.assertRegex(health[field], r"^[1-9][0-9]*s$")
                for mount in definition["volumes"]:
                    self.assertEqual(mount["type"], "bind")
                    self.assertEqual(mount["bind"], {"create_host_path": False})
                    self.assertRegex(mount["source"], r"^\./[a-z]+$")
                    self.assertTrue(mount["target"].startswith("/"))
                    self.assertNotIn("docker.sock", mount["target"])
                self.assertEqual(definition["logging"]["options"]["max-file"], "3")

    def test_gateway_resource_limits_and_numeric_owner(self):
        gateway = compose("gateway")["services"]["gateway"]
        self.assertIs(gateway["read_only"], True)
        self.assertNotIn("ports", gateway)
        self.assertNotIn("expose", gateway)
        self.assertEqual(gateway["cpus"], 1)
        self.assertEqual(gateway["mem_limit"], "512m")
        self.assertEqual(gateway["user"], "${GATEWAY_UID:-1000}:${GATEWAY_GID:-1000}")
        env = environment("gateway")
        for field in ("GATEWAY_UID", "GATEWAY_GID"):
            self.assertRegex(env[field], r"^[1-9][0-9]*$")
        self.assertEqual(
            gateway["tmpfs"], ["/tmp:rw,noexec,nosuid,nodev,size=16m,mode=1777"]
        )

    def test_gateway_config_mounts_socket_and_health_agree(self):
        gateway = compose("gateway")["services"]["gateway"]
        config = tomllib.loads(read("gateway/config.toml.example"))
        self.assertFalse(config["enabled"], "starting the daemon requires owner opt-in")
        self.assertFalse(config["ai"]["enabled"])
        self.assertFalse(config["ai"]["allow_insecure_http"])
        self.assertEqual(config["socket"], "/run/syslens-gateway.sock")
        self.assertEqual(config["database"], "/var/lib/syslens-gateway/gateway.sqlite")
        mounts = {mount["target"]: mount for mount in gateway["volumes"]}
        self.assertEqual(set(mounts), {"/etc/syslens-gateway", "/run", "/var/lib/syslens-gateway"})
        self.assertEqual(mounts["/etc/syslens-gateway"]["source"], "./config")
        self.assertIs(mounts["/etc/syslens-gateway"]["read_only"], True)
        for target, source in [("/run", "./run"), ("/var/lib/syslens-gateway", "./state")]:
            self.assertEqual(mounts[target]["source"], source)
            self.assertFalse(mounts[target].get("read_only", False))
        self.assertEqual(
            gateway["healthcheck"]["test"],
            ["CMD", "syslens-gateway", "--config", "/etc/syslens-gateway/config.toml", "health"],
        )
        certificate_paths = re.findall(r'^# (?:ca|client_cert|client_key) = "([^"]+)"', read("gateway/config.toml.example"), re.M)
        self.assertEqual(len(certificate_paths), 3)
        self.assertTrue(all(path.startswith("/etc/syslens-gateway/certs/") for path in certificate_paths))

    def test_ollama_is_lan_only_and_bounded(self):
        ollama = compose("ollama")["services"]["ollama"]
        env = ollama["environment"]
        for field in ("OLLAMA_NO_CLOUD", "OLLAMA_NUM_PARALLEL", "OLLAMA_MAX_LOADED_MODELS"):
            self.assertEqual(env[field], "1")
        self.assertEqual(env["OLLAMA_MAX_QUEUE"], "4")
        self.assertEqual(env["OLLAMA_CONTEXT_LENGTH"], "4096")
        self.assertEqual(env["OLLAMA_VULKAN"], "0")
        self.assertEqual(env["OLLAMA_HOST"], "0.0.0.0:11434")
        self.assertEqual(ollama["cpus"], "${OLLAMA_CPUS:-4}")
        self.assertEqual(ollama["mem_limit"], "${OLLAMA_MEMORY:-8g}")
        self.assertEqual(len(ollama["ports"]), 1)
        port = ollama["ports"][0]
        self.assertEqual(port["target"], 11434)
        self.assertEqual(port["published"], "11434")
        self.assertEqual(port["protocol"], "tcp")
        self.assertTrue(port["host_ip"].startswith("${OLLAMA_LAN_IP:?"))
        example = environment("ollama")
        address = ipaddress.IPv4Address(example["OLLAMA_LAN_IP"])
        self.assertTrue(address.is_private)
        self.assertFalse(address.is_unspecified or address.is_loopback)
        self.assertTrue(example["OLLAMA_IMAGE"].startswith("ollama/ollama:"))
        self.assertNotIn("latest", example["OLLAMA_IMAGE"])
        self.assertEqual(ollama["volumes"][0]["source"], "./data")
        self.assertEqual(ollama["volumes"][0]["target"], "/root/.ollama")
        self.assertEqual(ollama["healthcheck"]["test"], ["CMD", "ollama", "list"])
        self.assertNotIn("command", ollama)
        self.assertNotIn("entrypoint", ollama)

    def test_ollama_preflight_accepts_only_rfc1918_ipv4(self):
        preflight = ROOT / "ollama/preflight.sh"
        self.assertTrue(preflight.is_file())
        self.assertIn("./preflight.sh", read("ollama/start.sh"))
        self.assertIn("docker compose up", read("ollama/start.sh"))

        for address in ("10.0.0.1", "172.16.0.1", "172.31.255.254", "192.168.0.144"):
            with self.subTest(address=address):
                result = subprocess.run(
                    ["sh", str(preflight)],
                    env={**os.environ, "OLLAMA_LAN_IP": address},
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 0, result.stderr)

        for address in (None, "0.0.0.0", "127.0.0.1", "172.15.255.255", "172.016.0.1", "172.32.0.1", "192.167.1.1", "8.8.8.8", "::1", "192.168.0.1:11434", "192.168.0", "300.168.0.1"):
            with self.subTest(address=address):
                environment = dict(os.environ)
                if address is None:
                    environment.pop("OLLAMA_LAN_IP", None)
                else:
                    environment["OLLAMA_LAN_IP"] = address
                result = subprocess.run(
                    ["sh", str(preflight)],
                    env=environment,
                    capture_output=True,
                    text=True,
                    check=False,
                )
                self.assertEqual(result.returncode, 64)

    def test_ollama_start_preflights_the_deployment_env_before_docker(self):
        with tempfile.TemporaryDirectory() as directory:
            deployment = Path(directory) / "ollama"
            deployment.mkdir()
            for script in ("preflight.sh", "start.sh"):
                source = ROOT / "ollama" / script
                destination = deployment / script
                shutil.copy2(source, destination)
                destination.chmod(0o755)
            bin_directory = Path(directory) / "bin"
            bin_directory.mkdir()
            capture = Path(directory) / "docker.args"
            docker = bin_directory / "docker"
            docker.write_text('#!/bin/sh\nprintf "%s\\n" "$*" > "$DOCKER_CAPTURE"\n')
            docker.chmod(0o755)
            base_environment = {
                **os.environ,
                "PATH": f"{bin_directory}{os.pathsep}{os.environ['PATH']}",
                "DOCKER_CAPTURE": str(capture),
            }
            base_environment.pop("OLLAMA_LAN_IP", None)

            for contents in (
                "OLLAMA_LAN_IP=192.168.0.144\n",
                'OLLAMA_LAN_IP="192.168.0.144" # private bind\r\n',
                "export OLLAMA_LAN_IP='192.168.0.144' # private bind\n",
                "  OLLAMA_LAN_IP = 192.168.0.144\t# private bind\n",
            ):
                with self.subTest(contents=contents):
                    capture.unlink(missing_ok=True)
                    (deployment / ".env").write_text(contents, newline="")
                    result = subprocess.run(
                        [str(deployment / "start.sh")],
                        env=base_environment,
                        capture_output=True,
                        text=True,
                        check=False,
                    )
                    self.assertEqual(result.returncode, 0, result.stderr)
                    self.assertEqual(capture.read_text(), "compose up -d --wait ollama\n")

            capture.unlink()
            (deployment / ".env").write_text("OLLAMA_LAN_IP=0.0.0.0\n")
            result = subprocess.run(
                [str(deployment / "start.sh")],
                env=base_environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 64)
            self.assertFalse(capture.exists(), "invalid .env must fail before Docker")

            override_environment = {**base_environment, "OLLAMA_LAN_IP": "10.0.0.1"}
            result = subprocess.run(
                [str(deployment / "start.sh")],
                env=override_environment,
                capture_output=True,
                text=True,
                check=False,
            )
            self.assertEqual(result.returncode, 0, result.stderr)
            self.assertEqual(capture.read_text(), "compose up -d --wait ollama\n")

    def test_dockerfile_build_and_runtime_boundary(self):
        lines = []
        pending = ""
        for line in read("gateway/Dockerfile").splitlines():
            if not line or (line.startswith("#") and not pending):
                continue
            pending = f"{pending} {line.lstrip()}".strip()
            if pending.endswith("\\"):
                pending = pending[:-1].rstrip()
            else:
                lines.append(pending)
                pending = ""
        self.assertFalse(pending, "Dockerfile must not end with a continuation")
        instructions = [line.split(" ", 1) for line in lines]
        allowed = {"FROM", "ARG", "RUN", "WORKDIR", "COPY", "USER", "ENTRYPOINT", "CMD", "HEALTHCHECK"}
        self.assertTrue(all(instruction in allowed and argument for instruction, argument in instructions))
        stages = [argument for instruction, argument in instructions if instruction == "FROM"]
        self.assertEqual(stages, [
            "rust:1.95.0-bookworm@sha256:6258907abe69656e41cd992e0b705cdcfabcbbe3db374f92ed2d47121282d4a1 AS builder",
            "debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171 AS runtime",
        ])
        self.assertIn("ARG DEBIAN_SNAPSHOT=20250301T000000Z", lines)
        builder_install = next(line for line in lines if "apt-get install" in line)
        self.assertIn("snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT}", builder_install)
        self.assertIn("cmake=3.25.1-1", builder_install)
        self.assertNotIn("deb.debian.org", builder_install)
        self.assertIn("RUN cargo build --locked --release --package syslens-gateway", lines)
        runtime_start = next(index for index, line in enumerate(lines) if line.startswith("FROM debian:bookworm-slim@"))
        runtime = lines[runtime_start + 1:]
        copies = [line for line in runtime if line.startswith("COPY ")]
        self.assertEqual(copies, [
            "COPY --from=builder /build/target/release/syslens-gateway /usr/local/bin/syslens-gateway",
            "COPY --from=builder /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt",
        ])
        self.assertFalse(any("apt-get" in line for line in runtime), "runtime must not fetch packages")
        self.assertIn("USER 1000:1000", runtime)
        for instruction, argument in instructions:
            if instruction in {"ENTRYPOINT", "CMD"}:
                self.assertIsInstance(json.loads(argument), list)
        entrypoint = next(json.loads(arg) for op, arg in instructions if op == "ENTRYPOINT")
        self.assertEqual(entrypoint, ["syslens-gateway", "--config", "/etc/syslens-gateway/config.toml"])
        self.assertEqual(next(json.loads(arg) for op, arg in instructions if op == "CMD"), ["daemon"])
        health = next(arg for op, arg in instructions if op == "HEALTHCHECK")
        self.assertEqual(json.loads(health.split(" CMD ", 1)[1]), compose("gateway")["services"]["gateway"]["healthcheck"]["test"][1:])
        self.assertNotIn("--platform=linux/amd64", "\n".join(lines))
        self.assertNotIn("ollama", "\n".join(lines).lower())

    def test_secrets_and_model_data_stay_outside_image_and_repo(self):
        ignore = [line for line in read("gateway/Dockerfile.dockerignore").splitlines() if line and not line.startswith("#")]
        self.assertEqual(ignore[0], "**")
        self.assertEqual(set(ignore[1:]), {
            "!Cargo.toml", "!Cargo.lock", "!src/", "!src/**/", "!src/**/*.rs",
            "!crates/", "!crates/**/", "!crates/**/Cargo.toml", "!crates/**/*.rs",
        })
        ignored = set(read(".gitignore").splitlines())
        self.assertTrue({".env", "config/", "state/", "run/", "data/", "backups/", "*.key", "*.pem"} <= ignored)
        for project in ("gateway", "ollama"):
            text = read(f"{project}/compose.yaml") + read(f"{project}/.env.example")
            self.assertNotRegex(text, r"(?i)(?:ollama\s+(?:pull|run)|BEGIN .*PRIVATE KEY|sk-[A-Za-z0-9]{20})")
            self.assertNotIn("api_key", text.lower())

    def test_operations_and_offline_checks_are_documented_and_gated(self):
        gateway = read("gateway/README.md")
        ollama = read("ollama/README.md")
        for text, directory in [(gateway, "/home/orangepi/syslens-gateway"), (ollama, "/home/acemagic/ollama")]:
            self.assertIn(directory, text)
            for operation in ("docker compose pull", "docker compose up", "docker compose stop", "tar -", "rollback"):
                self.assertIn(operation, text)
        self.assertIn("docker compose exec ollama ollama pull qwen3:4b", ollama)
        self.assertNotIn("docker compose start ollama", ollama)
        self.assertIn("/api/tags", ollama)
        self.assertIn("DOCKER-USER", ollama)
        self.assertIn("sudo install -d -o 0 -g 0 -m 0700 data", ollama)
        self.assertIn("models set qwen3:4b", gateway)
        for workflow in ("ci.yml", "release-deb.yml"):
            self.assertIn("run: python3 deploy/test_assets.py", (ROOT.parent / ".github/workflows" / workflow).read_text())

    def test_duplicate_compose_keys_are_rejected(self):
        with self.assertRaisesRegex(ValueError, "duplicate key"):
            json.loads('{"read_only": true, "read_only": false}', object_pairs_hook=unique_object)


if __name__ == "__main__":
    unittest.main(verbosity=2)

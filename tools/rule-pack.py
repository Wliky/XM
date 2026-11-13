#!/usr/bin/env python3
"""规则包打包、签名与校验。"""

from __future__ import annotations

import argparse
import base64
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path

FORMAT = 1
ROOT = Path(__file__).resolve().parents[1]
DEFAULT_KEY_DIR = ROOT / "tools" / "keys"


def find_openssl() -> str:
    """定位 openssl 可执行文件。"""
    configured = os.environ.get("OPENSSL")
    if configured and Path(configured).exists():
        return configured
    found = shutil.which("openssl")
    if found:
        return found
    program_files = Path(os.environ.get("ProgramFiles", "C:/Program Files"))
    candidates = [
        program_files / "Git/usr/bin/openssl.exe",
        Path("D:/Software/Work/Tools/Git/usr/bin/openssl.exe"),
        Path("/usr/bin/openssl"),
        Path("/usr/local/bin/openssl"),
    ]
    for candidate in candidates:
        if candidate.exists():
            return str(candidate)
    raise SystemExit("找不到 openssl，可用 OPENSSL 环境变量指定路径")


def sha256_hex(data: bytes) -> str:
    """字节内容的 sha256 十六进制。"""
    return hashlib.sha256(data).hexdigest()


def signing_text(host_id: str, issued_at: int, rules_version: int, digest: str) -> bytes:
    """签名原文：format/hostId/issuedAt/rulesVersion/sha256，以 LF 分隔。"""
    return f"{FORMAT}\n{host_id}\n{issued_at}\n{rules_version}\n{digest}".encode("utf-8")


def read_payload(path: Path) -> tuple[bytes, str]:
    """读取规则原文及按 UTF-8 解码后的文本。"""
    raw = path.read_bytes()
    try:
        return raw, raw.decode("utf-8")
    except UnicodeDecodeError as error:
        raise SystemExit(f"规则文件不是 UTF-8：{path}（{error}）")


def load_meta(text: str) -> dict:
    """读取规则文件里的 hostId 与 rulesVersion。"""
    try:
        return json.loads(text)
    except json.JSONDecodeError as error:
        raise SystemExit(f"规则文件不是合法 JSON：{error}")


def sign_bytes(key: Path, text: bytes) -> str:
    """用 EC 私钥签名，返回 base64。"""
    openssl = find_openssl()
    with tempfile.TemporaryDirectory() as temp_dir:
        text_file = Path(temp_dir) / "signing.txt"
        sig_file = Path(temp_dir) / "signing.sig"
        text_file.write_bytes(text)
        result = subprocess.run(
            [openssl, "dgst", "-sha256", "-sign", str(key), "-out", str(sig_file), str(text_file)],
            capture_output=True,
            text=True,
        )
        if result.returncode != 0:
            raise SystemExit(f"openssl 签名失败：{result.stderr.strip()}")
        return base64.b64encode(sig_file.read_bytes()).decode("ascii")


def verify_bytes(pub: Path, text: bytes, signature: str) -> bool:
    """用公钥校验签名。"""
    openssl = find_openssl()
    with tempfile.TemporaryDirectory() as temp_dir:
        text_file = Path(temp_dir) / "signing.txt"
        sig_file = Path(temp_dir) / "signing.sig"
        text_file.write_bytes(text)
        try:
            sig_file.write_bytes(base64.b64decode(signature, validate=True))
        except ValueError:
            return False
        result = subprocess.run(
            [openssl, "dgst", "-sha256", "-verify", str(pub), "-signature", str(sig_file), str(text_file)],
            capture_output=True,
            text=True,
        )
        return result.returncode == 0


def command_pack(args: argparse.Namespace) -> int:
    """生成规则包信封。"""
    payload_path = Path(args.payload)
    raw, text = read_payload(payload_path)
    meta = load_meta(text)
    host_id = args.host or meta.get("hostId") or "wechat"
    rules_version = args.version if args.version is not None else meta.get("rulesVersion")
    if not isinstance(rules_version, int):
        raise SystemExit("缺少规则版本号：用 --version 指定，或在规则文件里写 rulesVersion")
    issued_at = args.issued_at or int(time.time() * 1000)
    digest = sha256_hex(raw)

    signature = ""
    if not args.unsigned:
        key = Path(args.key)
        if not key.exists():
            raise SystemExit(f"私钥不存在：{key}")
        signature = sign_bytes(key, signing_text(host_id, issued_at, rules_version, digest))

    envelope = {
        "format": FORMAT,
        "hostId": host_id,
        "issuedAt": issued_at,
        "rulesVersion": rules_version,
        "sha256": digest,
        "signature": signature,
        "payload": text,
    }
    out = Path(args.out) if args.out else ROOT / "build" / "rules" / f"{host_id}.pack.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    with out.open("w", encoding="utf-8", newline="\n") as handle:
        json.dump(envelope, handle, ensure_ascii=False, indent=2)
        handle.write("\n")

    state = "未签名" if args.unsigned else "已签名"
    print(f"规则包（{state}）：{out}")
    print(f"host={host_id} rulesVersion={rules_version} sha256={digest[:16]}…")
    return 0


def command_verify(args: argparse.Namespace) -> int:
    """校验规则包的摘要与签名。"""
    pack_path = Path(args.pack)
    try:
        envelope = json.loads(pack_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        print(f"规则包不可读：{error}")
        return 1

    payload = envelope.get("payload")
    if not isinstance(payload, str):
        print("规则包缺少 payload")
        return 1
    digest = sha256_hex(payload.encode("utf-8"))
    if digest.lower() != str(envelope.get("sha256", "")).lower():
        print(f"内容校验失败：sha256 应为 {digest}")
        return 1

    signature = envelope.get("signature") or ""
    if not signature:
        print("规则包未签名")
        return 1
    text = signing_text(
        str(envelope.get("hostId", "")),
        int(envelope.get("issuedAt", 0)),
        int(envelope.get("rulesVersion", 0)),
        digest,
    )
    if not verify_bytes(Path(args.pub), text, signature):
        print("验签失败")
        return 1

    print(f"验签通过：host={envelope.get('hostId')} version={envelope.get('rulesVersion')} sha256={digest[:16]}…")
    return 0


def command_keygen(args: argparse.Namespace) -> int:
    """生成 EC P-256 签名密钥。"""
    openssl = find_openssl()
    key_dir = Path(args.key_dir)
    private_key = key_dir / "rule-sign.pem"
    public_key = key_dir / "rule-sign.pub.pem"
    if private_key.exists():
        raise SystemExit(f"私钥已存在，不覆盖：{private_key}（丢了私钥就无法再发规则包，请先备份）")
    key_dir.mkdir(parents=True, exist_ok=True)
    generated = subprocess.run(
        [openssl, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(private_key)],
        capture_output=True,
        text=True,
    )
    if generated.returncode != 0:
        raise SystemExit(f"生成私钥失败：{generated.stderr.strip()}")
    exported = subprocess.run(
        [openssl, "ec", "-in", str(private_key), "-pubout", "-out", str(public_key)],
        capture_output=True,
        text=True,
    )
    if exported.returncode != 0:
        raise SystemExit(f"导出公钥失败：{exported.stderr.strip()}")
    print(f"私钥：{private_key}")
    print(f"公钥：{public_key}")
    print("把公钥内容整段粘到 RuleTrust.DEFAULT_PUBLIC_KEY")
    return 0


def build_parser() -> argparse.ArgumentParser:
    """命令行参数。"""
    parser = argparse.ArgumentParser(description="规则包打包、签名与校验")
    sub = parser.add_subparsers(dest="action", required=True)

    pack = sub.add_parser("pack", help="生成规则包")
    pack.add_argument("--payload", required=True, help="规则文件路径")
    pack.add_argument("--host", default="", help="宿主标识，默认取规则文件里的 hostId")
    pack.add_argument("--version", type=int, default=None, help="规则版本号，默认取规则文件里的 rulesVersion")
    pack.add_argument("--key", default=str(DEFAULT_KEY_DIR / "rule-sign.pem"), help="EC 私钥路径")
    pack.add_argument("--out", default="", help="输出路径，默认 build/rules/<hostId>.pack.json")
    pack.add_argument("--issued-at", type=int, default=0, help="签发时间（毫秒），默认当前时间")
    pack.add_argument("--unsigned", action="store_true", help="只生成未签名规则包")
    pack.set_defaults(func=command_pack)

    verify = sub.add_parser("verify", help="校验规则包")
    verify.add_argument("--pack", required=True, help="规则包路径")
    verify.add_argument("--pub", default=str(DEFAULT_KEY_DIR / "rule-sign.pub.pem"), help="EC 公钥路径")
    verify.set_defaults(func=command_verify)

    keygen = sub.add_parser("keygen", help="生成签名密钥")
    keygen.add_argument("--key-dir", default=str(DEFAULT_KEY_DIR), help="密钥目录")
    keygen.set_defaults(func=command_keygen)
    return parser


def main(argv: list[str]) -> int:
    """入口。"""
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))

from __future__ import annotations

import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path
from typing import Any

# ANSI styling
RESET = "\033[0m"
BOLD = "\033[1m"
GREEN = "\033[32m"
YELLOW = "\033[33m"
CYAN = "\033[36m"
RED = "\033[31m"
DIM = "\033[2m"

# Default open-access GGUF model weights on HuggingFace (no auth required)
DEFAULT_PLANNER_URL = (
    "https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/resolve/main/qwen2.5-0.5b-instruct-q4_k_m.gguf"
)


def download_file_with_progress(url: str, dest_path: Path, label: str = "Model") -> bool:
    """Download a file with a terminal progress bar. Writes atomically via .tmp file."""
    dest_path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = dest_path.with_suffix(dest_path.suffix + ".tmp")

    print(f"\n{CYAN}{BOLD}Downloading {label}:{RESET}")
    print(f"  Source URL: {url}")
    print(f"  Target:     {dest_path}")

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "CyberEDT-NEX/1.0"},
        )
        with urllib.request.urlopen(req, timeout=30) as response:
            total_size = int(response.headers.get("Content-Length", 0))
            downloaded = 0
            start_time = time.time()
            chunk_size = 128 * 1024  # 128 KB chunks

            with open(temp_path, "wb") as f_out:
                while True:
                    chunk = response.read(chunk_size)
                    if not chunk:
                        break
                    f_out.write(chunk)
                    downloaded += len(chunk)

                    elapsed = time.time() - start_time
                    speed = (downloaded / (1024 * 1024)) / elapsed if elapsed > 0 else 0

                    if total_size > 0:
                        pct = (downloaded / total_size) * 100
                        bar_len = 28
                        filled = int(bar_len * downloaded // total_size)
                        bar = "=" * filled + (">" if filled < bar_len else "")
                        bar = bar.ljust(bar_len, " ")
                        downloaded_mb = downloaded / (1024 * 1024)
                        total_mb = total_size / (1024 * 1024)
                        sys.stdout.write(
                            f"\r  [{bar}] {pct:5.1f}% ({downloaded_mb:5.1f} / {total_mb:5.1f} MB) {speed:4.1f} MB/s"
                        )
                        sys.stdout.flush()
                    else:
                        downloaded_mb = downloaded / (1024 * 1024)
                        sys.stdout.write(f"\r  Downloaded: {downloaded_mb:5.1f} MB ({speed:4.1f} MB/s)")
                        sys.stdout.flush()

        print()  # newline after progress bar
        if temp_path.exists():
            if dest_path.exists():
                dest_path.unlink()
            temp_path.rename(dest_path)

        file_size_mb = dest_path.stat().st_size / (1024 * 1024)
        print(f"{GREEN}[✓] Successfully downloaded {label} ({file_size_mb:.1f} MB){RESET}\n")
        return True

    except KeyboardInterrupt:
        print(f"\n{YELLOW}[!] Download cancelled by user.{RESET}")
        if temp_path.exists():
            temp_path.unlink()
        return False
    except Exception as exc:
        print(f"\n{RED}[!] Download failed: {exc}{RESET}")
        if temp_path.exists():
            temp_path.unlink()
        return False


def download_models(project_root: Path, config_data: dict[str, Any] | None = None) -> bool:
    """Download default GGUF model files into the models directory."""
    models_cfg = (config_data or {}).get("models", {})
    planner_rel = models_cfg.get("planner_model_path", "models/qwen3-0.6b-instruct.Q4_K_M.gguf")
    planner_path = project_root / planner_rel
    planner_url = models_cfg.get("planner_download_url", DEFAULT_PLANNER_URL)

    if planner_path.is_file():
        size_mb = planner_path.stat().st_size / (1024 * 1024)
        print(f"\n{YELLOW}[*] Primary model already exists:{RESET} {planner_path} ({size_mb:.1f} MB)")
        try:
            ans = input("    Do you want to re-download and overwrite? [y/N]: ").strip().lower()
            if ans not in ("y", "yes"):
                print("    Skipping download.")
                return True
        except (EOFError, KeyboardInterrupt):
            print()
            return False

    return download_file_with_progress(
        url=planner_url,
        dest_path=planner_path,
        label="Qwen GGUF Model (Planner)",
    )


def install_llama_cpp_runtime() -> bool:
    """Install llama-cpp-python into the current Python environment via pip."""
    print(f"\n{CYAN}{BOLD}Installing llama-cpp-python inference engine...{RESET}")
    print(f"  Interpreter: {sys.executable}")
    print("  Command:     pip install llama-cpp-python\n")

    cmd = [sys.executable, "-m", "pip", "install", "llama-cpp-python"]
    try:
        proc = subprocess.run(cmd)
        if proc.returncode == 0:
            print(f"\n{GREEN}[✓] Successfully installed llama-cpp-python!{RESET}\n")
            return True
        else:
            print(f"\n{RED}[!] pip install returned non-zero exit code: {proc.returncode}{RESET}\n")
            return False
    except Exception as exc:
        print(f"\n{RED}[!] Failed to run pip: {exc}{RESET}\n")
        return False

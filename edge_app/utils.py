import os
from pathlib import Path


def atomic_write_bytes(path: Path, data: bytes, mode: int = 0o644) -> None:
    """Atomic write: tmp file + fsync + os.replace (a crash or broken transfer never leaves a half-written file)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp_path = path.with_name(path.name + ".tmp")
    fd = os.open(tmp_path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
    with os.fdopen(fd, "wb") as f:
        f.write(data)
        f.flush()
        os.fsync(f.fileno())
    os.chmod(tmp_path, mode)  # O_CREAT mode does not apply to a tmp file left by an earlier crash
    os.replace(tmp_path, path)

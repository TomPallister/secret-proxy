#!/usr/bin/env python3
"""Race-safe file operations for the proxy-auth capability token."""

from __future__ import annotations

import os
import secrets
import stat
import sys
from pathlib import Path


class ProxyTokenError(Exception):
    """The token path, contents, or metadata are unsafe."""


def validate_token(data: bytes) -> str:
    if len(data) == 49 and data.endswith(b"\n"):
        body = data[:-1]
    elif len(data) == 48:
        body = data
    else:
        raise ProxyTokenError("invalid token")
    if any(byte not in b"0123456789abcdef" for byte in body):
        raise ProxyTokenError("invalid token")
    return body.decode("ascii")


def ensure_directory(path: str | Path, uid: int, gid: int) -> None:
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.name in ("", ".", ".."):
        raise ProxyTokenError("invalid directory")
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        components = candidate.parts[1:]
        for index, component in enumerate(components):
            if component in ("", ".", ".."):
                raise ProxyTokenError("invalid directory")
            try:
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            except FileNotFoundError:
                os.mkdir(component, 0o700, dir_fd=descriptor)
                next_descriptor = os.open(
                    component,
                    os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                    dir_fd=descriptor,
                )
            os.close(descriptor)
            descriptor = next_descriptor
            if index == len(components) - 1:
                os.fchown(descriptor, uid, gid)
                os.fchmod(descriptor, 0o700)
                metadata = os.fstat(descriptor)
                if (
                    metadata.st_uid != uid
                    or metadata.st_gid != gid
                    or stat.S_IMODE(metadata.st_mode) != 0o700
                ):
                    raise ProxyTokenError("unsafe directory metadata")
    except (OSError, ProxyTokenError) as error:
        raise ProxyTokenError("invalid directory") from error
    finally:
        os.close(descriptor)


def _open_parent(path: str | Path) -> tuple[int, str]:
    candidate = Path(path)
    if not candidate.is_absolute() or candidate.name in ("", ".", ".."):
        raise ProxyTokenError("invalid path")
    components = candidate.parent.parts
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY)
    try:
        for component in components[1:]:
            if component in ("", ".", ".."):
                raise ProxyTokenError("invalid path")
            next_descriptor = os.open(
                component,
                os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = next_descriptor
        return descriptor, candidate.name
    except Exception:
        os.close(descriptor)
        raise


def _read_regular(descriptor: int) -> tuple[str, bytes]:
    metadata = os.fstat(descriptor)
    if not stat.S_ISREG(metadata.st_mode):
        raise ProxyTokenError("not a regular file")
    chunks: list[bytes] = []
    remaining = 50
    while remaining:
        chunk = os.read(descriptor, remaining)
        if not chunk:
            break
        chunks.append(chunk)
        remaining -= len(chunk)
    raw = b"".join(chunks)
    if len(raw) == 50:
        raise ProxyTokenError("invalid token")
    return validate_token(raw), raw


def _open_regular(path: str | Path, flags: int = os.O_RDONLY) -> tuple[int, int]:
    parent_descriptor, name = _open_parent(path)
    try:
        descriptor = os.open(
            name,
            flags | os.O_NOFOLLOW | os.O_NONBLOCK,
            dir_fd=parent_descriptor,
        )
    except Exception:
        os.close(parent_descriptor)
        raise
    return parent_descriptor, descriptor


def read_token(path: str | Path) -> str:
    parent_descriptor = descriptor = -1
    try:
        parent_descriptor, descriptor = _open_regular(path)
        value, _ = _read_regular(descriptor)
        return value
    except (OSError, ProxyTokenError) as error:
        raise ProxyTokenError("invalid token") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def secure_private(path: str | Path, uid: int, gid: int) -> str:
    parent_descriptor = descriptor = -1
    try:
        parent_descriptor, descriptor = _open_regular(path)
        value, _ = _read_regular(descriptor)
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o600)
        metadata = os.fstat(descriptor)
        if (
            metadata.st_uid != uid
            or metadata.st_gid != gid
            or stat.S_IMODE(metadata.st_mode) != 0o600
        ):
            raise ProxyTokenError("unsafe metadata")
        return value
    except (OSError, ProxyTokenError) as error:
        raise ProxyTokenError("invalid private token") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def create_private(path: str | Path, data: bytes, uid: int, gid: int) -> None:
    validate_token(data)
    parent_descriptor = descriptor = -1
    name = ""
    created = False
    try:
        parent_descriptor, name = _open_parent(path)
        descriptor = os.open(
            name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=parent_descriptor,
        )
        created = True
        os.fchown(descriptor, uid, gid)
        os.fchmod(descriptor, 0o600)
        view = memoryview(data)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("token write made no progress")
            view = view[written:]
        os.fsync(descriptor)
    except (OSError, ProxyTokenError) as error:
        if created:
            try:
                os.unlink(name, dir_fd=parent_descriptor)
            except OSError:
                pass
        raise ProxyTokenError("could not create private token") from error
    finally:
        if descriptor >= 0:
            os.close(descriptor)
        if parent_descriptor >= 0:
            os.close(parent_descriptor)


def publish(
    source: str | Path,
    destination: str | Path,
    uid: int,
    gid: int | None,
) -> None:
    source_parent = source_descriptor = destination_parent = temporary_descriptor = -1
    temporary_name = ""
    try:
        source_parent, source_descriptor = _open_regular(source)
        _, raw = _read_regular(source_descriptor)
        destination_parent, destination_name = _open_parent(destination)
        effective_gid = os.fstat(destination_parent).st_gid if gid is None else gid
        try:
            existing = os.stat(
                destination_name,
                dir_fd=destination_parent,
                follow_symlinks=False,
            )
        except FileNotFoundError:
            existing = None
        if existing is not None and not stat.S_ISREG(existing.st_mode):
            raise ProxyTokenError("unsafe destination")

        temporary_name = f".{destination_name}.tmp.{os.getpid()}.{secrets.token_hex(8)}"
        temporary_descriptor = os.open(
            temporary_name,
            os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW,
            0o600,
            dir_fd=destination_parent,
        )
        os.fchown(temporary_descriptor, uid, effective_gid)
        os.fchmod(temporary_descriptor, 0o640)
        view = memoryview(raw)
        while view:
            written = os.write(temporary_descriptor, view)
            if written <= 0:
                raise OSError("token write made no progress")
            view = view[written:]
        os.fsync(temporary_descriptor)
        os.close(temporary_descriptor)
        temporary_descriptor = -1
        os.replace(
            temporary_name,
            destination_name,
            src_dir_fd=destination_parent,
            dst_dir_fd=destination_parent,
        )
        temporary_name = ""
        os.fsync(destination_parent)
        verified = os.open(
            destination_name,
            os.O_RDONLY | os.O_NOFOLLOW,
            dir_fd=destination_parent,
        )
        try:
            _read_regular(verified)
            metadata = os.fstat(verified)
            if (
                not stat.S_ISREG(metadata.st_mode)
                or metadata.st_uid != uid
                or metadata.st_gid != effective_gid
                or stat.S_IMODE(metadata.st_mode) != 0o640
            ):
                raise ProxyTokenError("unsafe published token")
        finally:
            os.close(verified)
    except (OSError, ProxyTokenError) as error:
        raise ProxyTokenError("could not publish token") from error
    finally:
        if temporary_descriptor >= 0:
            os.close(temporary_descriptor)
        if temporary_name and destination_parent >= 0:
            try:
                os.unlink(temporary_name, dir_fd=destination_parent)
            except OSError:
                pass
        if destination_parent >= 0:
            os.close(destination_parent)
        if source_descriptor >= 0:
            os.close(source_descriptor)
        if source_parent >= 0:
            os.close(source_parent)


def _integer(value: str) -> int:
    try:
        result = int(value, 10)
    except ValueError as error:
        raise ProxyTokenError("invalid identity") from error
    if result < 0:
        raise ProxyTokenError("invalid identity")
    return result


def main(arguments: list[str]) -> int:
    try:
        operation = arguments[1] if len(arguments) > 1 else ""
        if operation == "directory" and len(arguments) == 5:
            ensure_directory(arguments[2], _integer(arguments[3]), _integer(arguments[4]))
        elif operation == "create" and len(arguments) == 5:
            create_private(arguments[2], sys.stdin.buffer.read(50), _integer(arguments[3]), _integer(arguments[4]))
        elif operation == "secure" and len(arguments) == 5:
            secure_private(arguments[2], _integer(arguments[3]), _integer(arguments[4]))
        elif operation == "read" and len(arguments) == 3:
            sys.stdout.write(read_token(arguments[2]))
        elif operation == "publish" and len(arguments) == 6:
            publish(arguments[2], arguments[3], _integer(arguments[4]), _integer(arguments[5]))
        elif operation == "publish-shared" and len(arguments) == 5:
            publish(arguments[2], arguments[3], _integer(arguments[4]), None)
        else:
            raise ProxyTokenError("invalid invocation")
        return 0
    except (OSError, ProxyTokenError):
        print("ERROR: proxy auth token file is invalid.", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

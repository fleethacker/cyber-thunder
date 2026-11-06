"""Exact Windows generic credential reads under one non-impersonated logon token."""
from __future__ import annotations

import ctypes as c
from ctypes import wintypes as w
from functools import lru_cache
import os
import re


class _Credential(c.Structure):
    _fields_ = [("Flags", w.DWORD), ("Type", w.DWORD), ("TargetName", w.LPWSTR),
                ("Comment", w.LPWSTR), ("LastWritten", w.FILETIME), ("CredentialBlobSize", w.DWORD),
                ("CredentialBlob", c.c_void_p), ("Persist", w.DWORD), ("AttributeCount", w.DWORD),
                ("Attributes", c.c_void_p), ("TargetAlias", w.LPWSTR), ("UserName", w.LPWSTR)]


class _Luid(c.Structure):
    _fields_ = [("low", w.DWORD), ("high", w.LONG)]


class _Statistics(c.Structure):
    _fields_ = [("token", _Luid), ("authentication", _Luid), ("expires", c.c_int64),
                ("type", w.DWORD), ("impersonation", w.DWORD), ("charged", w.DWORD),
                ("available", w.DWORD), ("groups", w.DWORD), ("privileges", w.DWORD), ("modified", _Luid)]


class _Native:
    def __init__(self):
        if os.name != "nt":
            raise ValueError
        from .file_trust import _api
        self.tokens = _api()
        self.adv = c.WinDLL("advapi32", use_last_error=True)
        self.CredReadW = self.adv.CredReadW
        self.CredReadW.argtypes = [w.LPCWSTR, w.DWORD, w.DWORD, c.POINTER(c.POINTER(_Credential))]
        self.CredReadW.restype = w.BOOL
        self.CredFree = self.adv.CredFree
        self.CredFree.argtypes, self.CredFree.restype = [c.c_void_p], None

    def logon(self):
        native = self.tokens
        sids = native.trusted_sids()  # Also rejects any thread impersonation token.
        token = w.HANDLE()
        if not native.OpenProcessToken(native.GetCurrentProcess(), 8, c.byref(token)):
            raise ValueError
        try:
            stats, length = _Statistics(), w.DWORD()
            if not native.GetTokenInformation(token, 10, c.byref(stats), c.sizeof(stats), c.byref(length)):
                raise ValueError
            if length.value != c.sizeof(stats) or stats.type != 1:
                raise ValueError
            return sids, stats.token.low, stats.token.high, stats.authentication.low, stats.authentication.high
        finally:
            native.CloseHandle(token)


@lru_cache(maxsize=1)
def _api():
    return _Native()  # Native function bindings only, never credentials or user identity.


def read_password(target_name: str, username: str) -> bytes:
    """Generic blobs use UTF-16LE by this application's explicit provisioning contract."""
    failed = False
    try:
        if (not isinstance(target_name, str) or not re.fullmatch(
                r"CyberThunder/v1/[a-f0-9]{64}/[A-Za-z0-9_][A-Za-z0-9_.-]{0,63}", target_name)
                or not isinstance(username, str) or not 0 < len(username) <= 512 or "\0" in username):
            raise ValueError
        native = _api()
        before = native.logon()
        pointer = c.POINTER(_Credential)()
        try:
            if not native.CredReadW(target_name, 1, 0, c.byref(pointer)) or not pointer:
                raise ValueError
            item = pointer.contents
            if (item.Type != 1 or item.Flags != 0 or item.TargetName != target_name or item.UserName != username
                    or item.TargetAlias or item.Persist not in {1, 2} or item.AttributeCount != 0
                    or not item.CredentialBlob or not 0 < item.CredentialBlobSize <= 2560
                    or item.CredentialBlobSize % 2):
                raise ValueError
            value = c.string_at(item.CredentialBlob, item.CredentialBlobSize).decode("utf-16-le")
            if not value or "\0" in value or native.logon() != before:
                raise ValueError
            result = value.encode("utf-8")
        finally:
            if pointer:
                native.CredFree(pointer)
    except Exception:
        failed = True
    if failed:
        raise ValueError("Native credential is unavailable or does not match its binding") from None
    return result

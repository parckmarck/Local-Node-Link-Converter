from __future__ import annotations

import ctypes
import os
from ctypes import wintypes


class SecretCodec:
    """DPAPI protects the database with the current Windows user's credentials."""

    def __init__(self, protected: bool = True):
        self.protected = protected
        if protected and os.name != "nt":
            raise RuntimeError("Windows DPAPI is required for protected storage.")

    def encode(self, data: bytes) -> bytes:
        if not self.protected:
            return b"PLAIN1:" + data
        return b"DPAPI1:" + self._crypt(data, decrypt=False)

    def decode(self, data: bytes) -> bytes:
        if data.startswith(b"DPAPI1:"):
            if os.name != "nt":
                raise ValueError("This database belongs to a Windows user.")
            return self._crypt(data[7:], decrypt=True)
        if not self.protected and data.startswith(b"PLAIN1:"):
            return data[7:]
        raise ValueError("Unrecognized or unprotected database payload.")

    @staticmethod
    def _crypt(data: bytes, *, decrypt: bool) -> bytes:
        class Blob(ctypes.Structure):
            _fields_ = [
                ("cbData", wintypes.DWORD),
                ("pbData", ctypes.POINTER(ctypes.c_ubyte)),
            ]

        crypt32 = ctypes.WinDLL("crypt32", use_last_error=True)
        kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
        input_buffer = ctypes.create_string_buffer(data)
        source = Blob(len(data), ctypes.cast(input_buffer, ctypes.POINTER(ctypes.c_ubyte)))
        destination = Blob()
        operation = crypt32.CryptUnprotectData if decrypt else crypt32.CryptProtectData
        operation.argtypes = [
            ctypes.POINTER(Blob),
            ctypes.c_void_p,
            ctypes.POINTER(Blob),
            ctypes.c_void_p,
            ctypes.c_void_p,
            wintypes.DWORD,
            ctypes.POINTER(Blob),
        ]
        operation.restype = wintypes.BOOL
        kernel32.LocalFree.argtypes = [ctypes.c_void_p]
        kernel32.LocalFree.restype = ctypes.c_void_p
        if not operation(
            ctypes.byref(source), None, None, None, None, 1, ctypes.byref(destination)
        ):
            raise OSError("Windows could not protect/unprotect local data.")
        try:
            return ctypes.string_at(destination.pbData, destination.cbData)
        finally:
            kernel32.LocalFree(destination.pbData)

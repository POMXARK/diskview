#!/usr/bin/env python3
"""hdd_watch — монитор нагрузки физических дисков и дискового I/O процессов на Windows.

Запуск:
  python hdd_watch.py            # все диски, обновление каждые 2 с
  python hdd_watch.py S:         # фильтр по диску S:
  python hdd_watch.py S: --once  # один замер и выход
"""
import argparse
import ctypes
from ctypes import wintypes
import os
import sys
import time

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")

if os.name != "nt":
    sys.exit("hdd_watch.py работает только на Windows.")

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
pdh = ctypes.WinDLL("pdh", use_last_error=True)

TH32CS_SNAPPROCESS = 0x00000002
PROCESS_QUERY_LIMITED_INFORMATION = 0x1000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

PDH_FMT_DOUBLE = 0x00000200
PDH_MORE_DATA = 0x800007D2
PDH_NO_DATA = 0x800007D5


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [
        ("dwSize", wintypes.DWORD),
        ("cntUsage", wintypes.DWORD),
        ("th32ProcessID", wintypes.DWORD),
        ("th32DefaultHeapID", ctypes.POINTER(ctypes.c_ulong)),
        ("th32ModuleID", wintypes.DWORD),
        ("cntThreads", wintypes.DWORD),
        ("th32ParentProcessID", wintypes.DWORD),
        ("pcPriClassBase", ctypes.c_long),
        ("dwFlags", wintypes.DWORD),
        ("szExeFile", wintypes.WCHAR * 260),
    ]


class IO_COUNTERS(ctypes.Structure):
    _fields_ = [
        ("ReadOperationCount", ctypes.c_uint64),
        ("WriteOperationCount", ctypes.c_uint64),
        ("OtherOperationCount", ctypes.c_uint64),
        ("ReadTransferCount", ctypes.c_uint64),
        ("WriteTransferCount", ctypes.c_uint64),
        ("OtherTransferCount", ctypes.c_uint64),
    ]


class PDH_FMT_COUNTERVALUE(ctypes.Structure):
    _fields_ = [
        ("CStatus", wintypes.DWORD),
        ("_pad", wintypes.DWORD),
        ("doubleValue", ctypes.c_double),
    ]


class PDH_FMT_COUNTERVALUE_ITEM_W(ctypes.Structure):
    _fields_ = [
        ("szName", wintypes.LPWSTR),
        ("FmtValue", PDH_FMT_COUNTERVALUE),
    ]


kernel32.CreateToolhelp32Snapshot.argtypes = [wintypes.DWORD, wintypes.DWORD]
kernel32.CreateToolhelp32Snapshot.restype = wintypes.HANDLE
kernel32.Process32FirstW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32FirstW.restype = wintypes.BOOL
kernel32.Process32NextW.argtypes = [wintypes.HANDLE, ctypes.POINTER(PROCESSENTRY32W)]
kernel32.Process32NextW.restype = wintypes.BOOL
kernel32.OpenProcess.argtypes = [wintypes.DWORD, wintypes.BOOL, wintypes.DWORD]
kernel32.OpenProcess.restype = wintypes.HANDLE
kernel32.GetProcessIoCounters.argtypes = [wintypes.HANDLE, ctypes.POINTER(IO_COUNTERS)]
kernel32.GetProcessIoCounters.restype = wintypes.BOOL
kernel32.QueryFullProcessImageNameW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    wintypes.LPWSTR,
    ctypes.POINTER(wintypes.DWORD),
]
kernel32.QueryFullProcessImageNameW.restype = wintypes.BOOL
kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
kernel32.CloseHandle.restype = wintypes.BOOL

pdh.PdhOpenQueryW.argtypes = [wintypes.LPCWSTR, ctypes.c_void_p, ctypes.POINTER(wintypes.HANDLE)]
pdh.PdhOpenQueryW.restype = wintypes.DWORD
pdh.PdhAddEnglishCounterW.argtypes = [
    wintypes.HANDLE,
    wintypes.LPCWSTR,
    ctypes.c_void_p,
    ctypes.POINTER(wintypes.HANDLE),
]
pdh.PdhAddEnglishCounterW.restype = wintypes.DWORD
pdh.PdhCollectQueryData.argtypes = [wintypes.HANDLE]
pdh.PdhCollectQueryData.restype = wintypes.DWORD
pdh.PdhGetFormattedCounterArrayW.argtypes = [
    wintypes.HANDLE,
    wintypes.DWORD,
    ctypes.POINTER(wintypes.DWORD),
    ctypes.POINTER(wintypes.DWORD),
    ctypes.c_void_p,
]
pdh.PdhGetFormattedCounterArrayW.restype = wintypes.DWORD
pdh.PdhCloseQuery.argtypes = [wintypes.HANDLE]
pdh.PdhCloseQuery.restype = wintypes.DWORD


DISK_COUNTERS = {
    "busy": r"\PhysicalDisk(*)\% Disk Time",
    "queue": r"\PhysicalDisk(*)\Current Disk Queue Length",
    "r_iops": r"\PhysicalDisk(*)\Disk Reads/sec",
    "w_iops": r"\PhysicalDisk(*)\Disk Writes/sec",
    "r_bps": r"\PhysicalDisk(*)\Disk Read Bytes/sec",
    "w_bps": r"\PhysicalDisk(*)\Disk Write Bytes/sec",
    "avg_ms": r"\PhysicalDisk(*)\Avg. Disk sec/Read",
}


class DiskMonitor:
    def __init__(self):
        self.query = wintypes.HANDLE()
        st = pdh.PdhOpenQueryW(None, None, ctypes.byref(self.query))
        if st != 0:
            raise OSError("PdhOpenQueryW failed: 0x%08x" % st)
        self.handles = {}
        for k, path in DISK_COUNTERS.items():
            h = wintypes.HANDLE()
            st = pdh.PdhAddEnglishCounterW(self.query, path, None, ctypes.byref(h))
            if st != 0:
                raise OSError("PdhAddEnglishCounterW(%s) failed: 0x%08x" % (path, st))
            self.handles[k] = h
        pdh.PdhCollectQueryData(self.query)

    def close(self):
        if self.query:
            pdh.PdhCloseQuery(self.query)
            self.query = None

    def _read_array(self, h):
        buf_size = wintypes.DWORD(0)
        item_count = wintypes.DWORD(0)
        st = pdh.PdhGetFormattedCounterArrayW(
            h, PDH_FMT_DOUBLE, ctypes.byref(buf_size), ctypes.byref(item_count), None
        )
        if st == PDH_NO_DATA:
            return {}
        if st != PDH_MORE_DATA and st != 0:
            raise OSError("PdhGetFormattedCounterArrayW size failed: 0x%08x" % st)
        if buf_size.value == 0:
            return {}
        buf = (ctypes.c_ubyte * buf_size.value)()
        st = pdh.PdhGetFormattedCounterArrayW(
            h, PDH_FMT_DOUBLE, ctypes.byref(buf_size), ctypes.byref(item_count), ctypes.byref(buf)
        )
        if st != 0:
            raise OSError("PdhGetFormattedCounterArrayW read failed: 0x%08x" % st)
        items = ctypes.cast(buf, ctypes.POINTER(PDH_FMT_COUNTERVALUE_ITEM_W))
        out = {}
        for i in range(item_count.value):
            it = items[i]
            if it.szName and it.FmtValue.CStatus in (0, 1):
                out[it.szName] = it.FmtValue.doubleValue
        return out

    def sample(self, drive_filter=""):
        st = pdh.PdhCollectQueryData(self.query)
        if st != 0:
            raise OSError("PdhCollectQueryData failed: 0x%08x" % st)
        raw = {k: self._read_array(h) for k, h in self.handles.items()}
        disks = {}
        for name in raw["busy"]:
            if name == "_Total":
                continue
            if drive_filter and drive_filter not in name.upper().split():
                continue
            disks[name] = {
                "busy": raw["busy"].get(name, 0.0),
                "queue": raw["queue"].get(name, 0.0),
                "r_iops": raw["r_iops"].get(name, 0.0),
                "w_iops": raw["w_iops"].get(name, 0.0),
                "r_bps": raw["r_bps"].get(name, 0.0),
                "w_bps": raw["w_bps"].get(name, 0.0),
                "avg_ms": raw["avg_ms"].get(name, 0.0) * 1000.0,
            }
        return disks


def snapshot_procs():
    snap = kernel32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if snap == INVALID_HANDLE_VALUE:
        return {}
    procs = {}
    try:
        pe = PROCESSENTRY32W()
        pe.dwSize = ctypes.sizeof(PROCESSENTRY32W)
        ok = kernel32.Process32FirstW(snap, ctypes.byref(pe))
        while ok:
            pid = pe.th32ProcessID
            if pid > 4:
                h = kernel32.OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, False, pid)
                if h:
                    try:
                        io = IO_COUNTERS()
                        if kernel32.GetProcessIoCounters(h, ctypes.byref(io)):
                            buf = ctypes.create_unicode_buffer(520)
                            blen = wintypes.DWORD(520)
                            path = pe.szExeFile
                            if kernel32.QueryFullProcessImageNameW(h, 0, buf, ctypes.byref(blen)):
                                path = buf.value
                            procs[pid] = (
                                pe.szExeFile,
                                path,
                                io.ReadOperationCount,
                                io.WriteOperationCount,
                                io.ReadTransferCount,
                                io.WriteTransferCount,
                            )
                    finally:
                        kernel32.CloseHandle(h)
            ok = kernel32.Process32NextW(snap, ctypes.byref(pe))
    finally:
        kernel32.CloseHandle(snap)
    return procs


def norm_drive(d):
    d = (d or "").strip().upper()
    if not d:
        return ""
    if len(d) == 1 and d.isalpha():
        return d + ":"
    if len(d) >= 2 and d[0].isalpha() and d[1] == ":":
        return d[:2]
    return d


def render(disks, proc_rows, dt, top_n):
    print("=" * 96)
    print("[%s] Интервал: %.2f с | Физические диски" % (time.strftime("%H:%M:%S"), dt))
    print("%-14s %7s %6s %17s %17s %8s  %s" % (
        "Диск", "%Busy", "Очер.", "Чтение MB/s(IOPS)", "Запись MB/s(IOPS)", "Avg ms", "Статус"
    ))
    if not disks:
        print("(нет данных по выбранному диску)")
    for name in sorted(disks):
        m = disks[name]
        over = m["busy"] >= 80.0 or m["queue"] >= 2.0 or m["avg_ms"] >= 50.0
        flag = "[ПЕРЕГРУЗКА]" if over else "OK"
        r_str = "%5.1f (%5.0f)" % (m["r_bps"] / (1 << 20), m["r_iops"])
        w_str = "%5.1f (%5.0f)" % (m["w_bps"] / (1 << 20), m["w_iops"])
        print("%-14s %6.0f%% %6.1f %17s %17s %8.1f  %s" % (
            name[:14], m["busy"], m["queue"], r_str, w_str, m["avg_ms"], flag
        ))

    print("-" * 96)
    print("Топ-%d процессов по дисковому I/O (все диски, включая кеш):" % top_n)
    print("%7s %-24s %10s %10s %7s %7s  %s" % (
        "PID", "Процесс", "Чтен.KB/s", "Зап.KB/s", "R-IOPS", "W-IOPS", "Путь"
    ))
    shown = proc_rows[:top_n]
    if not shown:
        print("(активного дискового I/O у процессов не зафиксировано)")
    for r in shown:
        print("%7d %-24s %10.1f %10.1f %7.0f %7.0f  %s" % (
            r[0], r[1][:24], r[2], r[3], r[4], r[5], r[6]
        ))
    if shown:
        top = shown[0]
        print("Главный источник I/O сейчас: %s (PID %d) — чтение %.1f KB/s (%.0f IOPS), запись %.1f KB/s (%.0f IOPS)" % (
            top[1], top[0], top[2], top[4], top[3], top[5]
        ))


def main():
    ap = argparse.ArgumentParser(description="Монитор нагрузки HDD и процессов I/O (Windows)")
    ap.add_argument("drive", nargs="?", default="", help="Буква диска, например S: (по умолчанию все)")
    ap.add_argument("--interval", type=float, default=2.0, help="Интервал замера в секундах (по умолчанию 2.0)")
    ap.add_argument("--top", type=int, default=15, help="Сколько процессов показывать (по умолчанию 15)")
    ap.add_argument("--once", action="store_true", help="Сделать один замер и выйти")
    args = ap.parse_args()

    drive_filter = norm_drive(args.drive)
    mon = DiskMonitor()
    try:
        prev_p = snapshot_procs()
        t0 = time.monotonic()
        while True:
            time.sleep(max(0.2, args.interval))
            t1 = time.monotonic()
            dt = max(0.05, t1 - t0)
            disks = mon.sample(drive_filter)
            cur_p = snapshot_procs()

            rows = []
            for pid, cur in cur_p.items():
                prev = prev_p.get(pid)
                if not prev:
                    continue
                dr_ops = max(0, cur[2] - prev[2])
                dw_ops = max(0, cur[3] - prev[3])
                dr_b = max(0, cur[4] - prev[4])
                dw_b = max(0, cur[5] - prev[5])
                if dr_ops == 0 and dw_ops == 0 and dr_b == 0 and dw_b == 0:
                    continue
                r_kbps = (dr_b / 1024.0) / dt
                w_kbps = (dw_b / 1024.0) / dt
                r_iops = dr_ops / dt
                w_iops = dw_ops / dt
                rows.append((pid, cur[0], r_kbps, w_kbps, r_iops, w_iops, cur[1]))

            rows.sort(key=lambda x: (x[2] + x[3], x[4] + x[5]), reverse=True)
            if not args.once:
                os.system("cls")
            render(disks, rows, dt, args.top)
            if args.once:
                break
            prev_p = cur_p
            t0 = t1
    except KeyboardInterrupt:
        pass
    finally:
        mon.close()


if __name__ == "__main__":
    main()

import sys
import json
import re
from pathlib import Path

INPUT = Path("telemetry/zimbra-shell-test.txt")
OUTPUT = Path("telemetry/zimbra-shell-test.json")


def parse_execve_blocks(text: str) -> list[dict]:
    events = []

    # ausearch separates audit events with ----
    blocks = text.split("----")

    for block in blocks:
        if "type=EXECVE" not in block:
            continue

        event = {}

        # Timestamp from the EXECVE line
        timestamp_match = re.search(
            r"type=EXECVE msg=audit\(([^:]+:[^:]+:[^:]+)",
            block,
        )
        if timestamp_match:
            event["timestamp"] = timestamp_match.group(1)

        # Full command from PROCTITLE
        proctitle_match = re.search(
            r"type=PROCTITLE .*?proctitle=(.+)",
            block,
        )
        if proctitle_match:
            event["command"] = proctitle_match.group(1).strip()

        # Executable, PID, PPID, UID, key from SYSCALL
        syscall_line_match = re.search(
            r"type=SYSCALL .+",
            block,
        )

        if syscall_line_match:
            syscall_line = syscall_line_match.group(0)

            ppid_match = re.search(r"(?:^|\s)ppid=(\d+)", syscall_line)
            pid_match = re.search(r"(?:^|\s)pid=(\d+)", syscall_line)
            uid_match = re.search(r"(?:^|\s)uid=([^\s]+)", syscall_line)
            exe_match = re.search(r"(?:^|\s)exe=([^\s]+)", syscall_line)
            key_match = re.search(r"(?:^|\s)key=([^\s]+)", syscall_line)

            if ppid_match:
                event["ppid"] = int(ppid_match.group(1))

            if pid_match:
                event["pid"] = int(pid_match.group(1))

            if uid_match:
                event["uid"] = uid_match.group(1)

            if exe_match:
                event["exe"] = exe_match.group(1)

            if key_match:
                event["key"] = key_match.group(1)

        if event:
            events.append(event)

    return events

def parse_file_create_blocks(text: str) -> list[dict]:
    events = []

    for block in text.split("----"):
        if "nametype=CREATE" not in block:
            continue

        path_match = re.search(
            r"type=PATH .*?name=(/[^\s]+).*?nametype=CREATE",
            block,
        )

        syscall_match = re.search(
            r"type=SYSCALL .+",
            block,
        )

        if not path_match or not syscall_match:
            continue

        syscall_line = syscall_match.group(0)

        def get_field(name: str):
            match = re.search(
                rf"(?:^|\s){name}=([^\s]+)",
                syscall_line,
            )
            return match.group(1) if match else None

        timestamp_match = re.search(
            r"msg=audit\(([^)]+)\)",
            syscall_line,
        )

        timestamp = None
        audit_id = None

        if timestamp_match:
            timestamp, _, audit_id = timestamp_match.group(1).rpartition(":")

        event = {
            "event_type": "file_create",
            "timestamp": timestamp,
            "audit_id": audit_id,
            "created_path": path_match.group(1),
            "syscall": get_field("syscall"),
            "success": get_field("success"),
            "uid": get_field("uid"),
            "exe": get_field("exe"),
            "key": get_field("key"),
        }

        events.append(event)

    return events

def main():
    source = Path(sys.argv[1]) if len(sys.argv) > 1 else INPUT
    destination = Path(sys.argv[2]) if len(sys.argv) > 2 else OUTPUT

    raw = source.read_text(encoding="utf-8")

    events = (
        parse_execve_blocks(raw)
        + parse_file_create_blocks(raw)
    )

    destination.write_text(
        json.dumps(events, indent=2),
        encoding="utf-8",
    )

    print(f"Parsed {len(events)} events")
    print(f"Saved structured telemetry to {destination}")

if __name__ == "__main__":
    main()

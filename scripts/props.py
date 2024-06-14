import sys
import hashlib
import pefile


def entropy(data) -> float:
    import math
    from collections import Counter

    if not data:
        return 0.0

    occurences = Counter(bytearray(data))

    entropy = 0
    for x in occurences.values():
        p_x = float(x) / len(data)
        entropy -= p_x * math.log(p_x, 2)

    return entropy


class PEHelper:
    def __init__(self, fileName) -> None:
        self.pe = pefile.PE(fileName)

    def is_what(self) -> str:
        return next(key for key in ("exe", "dll", "driver") if getattr(self.pe, f"is_{key}")())

    def entropy(self) -> float:
        return entropy(self.pe.__data__)

    def sections(self) -> dict:
        return dict(map(self._sections, self.pe.sections))

    def _sections(self, section) -> tuple:
        name = "".join(
            filter(str.isprintable, section.Name.decode(
                "UTF-8", errors="replace"))
        )
        return (
            name,
            {
                "Raw Size": section.SizeOfRawData,
                "Entropy": entropy(section.get_data()),
            },
        )

    def imports(self) -> dict:
        if hasattr(self.pe, "DIRECTORY_ENTRY_IMPORT"):
            return {
                entry.dll.decode().lower(): [imp.name.decode() for imp in entry.imports]
                for entry in self.pe.DIRECTORY_ENTRY_IMPORT
            }
        return {}

    def exports(self) -> dict:
        if self.pe.OPTIONAL_HEADER.DATA_DIRECTORY[0].Size:
            return {
                (exp.name.decode() if exp.name is not None else ""): exp.ordinal
                for exp in self.pe.DIRECTORY_ENTRY_EXPORT.symbols
            }
        return {}

    def symbols(self) -> list:
        return [data.entry.PdbFileName.decode() for data in
                self.pe.DIRECTORY_ENTRY_DEBUG if hasattr(data.entry, "PdbFileName")]

    def arch(self) -> str:
        if hex(self.pe.OPTIONAL_HEADER.Magic) == "0x10b":
            return "x86"
        elif hex(self.pe.OPTIONAL_HEADER.Magic) == "0x20b":
            return "x64_86"

    def timestamp(self) -> str:
        import datetime

        epoch_time = self.pe.FILE_HEADER.TimeDateStamp
        date_time = datetime.datetime.fromtimestamp(epoch_time)
        return date_time

    def size(self) -> int:
        return len(self.pe.__data__)

    def md5(self) -> str:
        return hashlib.md5(self.pe.__data__).hexdigest()

    def sha256(self) -> str:
        return hashlib.sha256(self.pe.__data__).hexdigest()


if __name__ == "__main__":
    if len(sys.argv) != 2:
        print(f"Usage: {sys.argv[0]} <PE File>")
        sys.exit(1)

    pe = PEHelper(sys.argv[1])
    information = {
        "PE Type": pe.is_what(),
        "PE Size": (lambda: f"{len(pe.pe.__data__) / 1000 } KB")(),
        "Architecture": pe.arch(),
        "Total Entropy": pe.entropy(),
        "MD5 hash": pe.md5(),
        "SHA256 hash": pe.sha256(),
        "Timestamp": pe.timestamp(),
        "Debug Symbols": (lambda x: ",".join(x) if x else "")(pe.symbols()),
        ###############################
        "Sections": pe.sections(),
        "Imports": pe.imports(),
        "Exports": pe.exports(),
    }

    def print_info(key, value, indent=0):
        prefix = '\t' * indent + (f"{key}:\t" if key else "")
        if isinstance(value, dict):
            print(prefix)
            for sub_key, sub_value in value.items():
                print_info(sub_key, sub_value, indent + 1)
        elif isinstance(value, list):
            print(prefix)
            for item in value:
                print_info("", item, indent + 1)
        else:
            print(f"{prefix}{value}")

    for key, value in information.items():
        print_info(key, value)

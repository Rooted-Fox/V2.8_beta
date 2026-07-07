"""Base interface every scanner wrapper implements."""
from __future__ import annotations

import shutil
import subprocess
from abc import ABC, abstractmethod
from typing import List

from models import RawFinding


class ScannerNotInstalled(RuntimeError):
    pass


class BaseScanner(ABC):
    """Wraps one scanning tool and normalizes its output.

    binary_name/run_subprocess are here for any future tool that's driven
    via the command line (e.g. Nuclei, Nikto) - the current ZAP scanner
    talks to a REST API instead and doesn't use them.
    """

    binary_name: str = ""

    def ensure_installed(self) -> None:
        if self.binary_name and shutil.which(self.binary_name) is None:
            raise ScannerNotInstalled(
                f"'{self.binary_name}' not found on PATH. Install it before running this scanner."
            )

    def run_subprocess(self, args: List[str]) -> str:
        result = subprocess.run(args, capture_output=True, text=True, timeout=900)
        return result.stdout

    @abstractmethod
    def scan(self) -> List[RawFinding]:
        """Run the tool against its configured target and return normalized findings."""
        raise NotImplementedError

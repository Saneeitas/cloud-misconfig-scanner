"""Check registry — auto-discovers check classes from the checks/ directory."""

import importlib
import pkgutil
from pathlib import Path

from scanner.base_check import BaseCheck


class CheckRegistry:
    """Discovers and registers all BaseCheck subclasses from checks/ packages."""

    @classmethod
    def discover(cls) -> list[type[BaseCheck]]:
        """Scan checks/aws/ and checks/azure/ for BaseCheck subclasses.

        Returns a list of check classes (not instances) — the engine
        instantiates them when needed.
        """
        checks: list[type[BaseCheck]] = []
        checks_package_path = Path(__file__).parent / "checks"

        for provider_dir in ["aws", "azure"]:
            package_path = checks_package_path / provider_dir
            if not package_path.exists():
                continue

            package_name = f"scanner.checks.{provider_dir}"

            for module_info in pkgutil.iter_modules([str(package_path)]):
                module_name = f"{package_name}.{module_info.name}"
                try:
                    module = importlib.import_module(module_name)
                except Exception:
                    continue

                for attr_name in dir(module):
                    attr = getattr(module, attr_name)
                    if (
                        isinstance(attr, type)
                        and issubclass(attr, BaseCheck)
                        and attr is not BaseCheck
                    ):
                        checks.append(attr)

        return checks

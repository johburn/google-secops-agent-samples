"""Convenience entrypoint re-exporting `soar_playbook/soar_custom_action_ide.py`."""

from .soar_playbook.soar_custom_action_ide import (
    INTEGRATION_NAME,
    SCRIPT_NAME,
    SiemplifyAction,
    build_soar_html_widget,
    extract_soar_entities,
    main,
)

__all__ = [
    "INTEGRATION_NAME",
    "SCRIPT_NAME",
    "SiemplifyAction",
    "build_soar_html_widget",
    "extract_soar_entities",
    "main",
]

if __name__ == "__main__":
    import json

    print(json.dumps(main(), indent=2, ensure_ascii=False))

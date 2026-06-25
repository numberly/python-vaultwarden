def env_from_ci():
    import os
    from pathlib import Path

    if os.environ.get("BITWARDEN_URL", None) is not None:
        return

    import yaml

    obj = yaml.safe_load(Path(".github/workflows/ci.yml").read_text())
    for k, v in obj["jobs"]["test"]["steps"][-1]["env"].items():
        os.environ[k] = v

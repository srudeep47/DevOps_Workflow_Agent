import subprocess
import tempfile
import os


def validate_fixed_yaml(yaml_content):
    with tempfile.TemporaryDirectory() as tmpdir:

        yaml_file = os.path.join(tmpdir, "fixed_pipeline.yaml")

        with open(yaml_file, "w", encoding="utf-8") as f:
            f.write(yaml_content)

        result = subprocess.run(
            [
                "docker",
                "run",
                "--rm",
                "-v",
                f"{os.path.abspath(yaml_file)}:/workspace/pipeline.yaml",
                "devops-yaml-validator",
                "python",
                "-c",
                "import yaml; yaml.safe_load(open('/workspace/pipeline.yaml')); print('YAML VALIDATION PASSED')"
            ],
            capture_output=True,
            text=True,
            timeout=60,
        )

        return {
            "success": result.returncode == 0,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "exit_code": result.returncode,
        }
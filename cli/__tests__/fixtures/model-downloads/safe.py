from huggingface_hub import snapshot_download
from transformers import AutoModel
import hashlib
import requests

AutoModel.from_pretrained("./models/local")
AutoModel.from_pretrained("models/cache/local-model")
AutoModel.from_pretrained(
    "acme/reviewed-model",
    revision="0123456789abcdef0123456789abcdef01234567",
)
snapshot_download(
    repo_id="acme/reviewed-weights",
    revision="0123456789abcdef0123456789abcdef01234567",
)
requests.get(
    "https://huggingface.co/acme/model/resolve/0123456789abcdef0123456789abcdef01234567/model.safetensors"
)
response = requests.get("https://models.example.invalid/release/model.safetensors")
assert hashlib.sha256(response.content).hexdigest() == (
    "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
)

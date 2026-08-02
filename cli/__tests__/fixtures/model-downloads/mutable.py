import torch
import requests
from huggingface_hub import hf_hub_download, snapshot_download
from transformers import AutoModel

AutoModel.from_pretrained("acme/mutable-model", trust_remote_code=True)
snapshot_download(repo_id="acme/mutable-weights")
model_path = hf_hub_download("acme/pickled-model", filename="model.pkl")
requests.get("https://huggingface.co/acme/model/resolve/main/model.safetensors")
model = torch.load(model_path)

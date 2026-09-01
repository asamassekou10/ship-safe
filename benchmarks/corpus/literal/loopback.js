// A local model server, reached over loopback.
const INFERENCE_URL = "http://127.0.0.1:1234/v1";

export async function infer(prompt) {
  return fetch(`${INFERENCE_URL}/completions`, { method: "POST", body: prompt });
}

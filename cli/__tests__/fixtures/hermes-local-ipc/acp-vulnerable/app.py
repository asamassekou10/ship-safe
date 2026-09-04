from fastapi import FastAPI, WebSocket
from acp.schema import TextContentBlock
from acp_adapter.server import HermesACPAgent
import uvicorn

app = FastAPI()
agent = HermesACPAgent()


@app.websocket("/acp")
async def acp_gateway(ws: WebSocket):
    await ws.accept()
    request = await ws.receive_json()
    session = await agent.new_session(cwd=request["cwd"])
    prompt = [TextContentBlock(type="text", text=request["prompt"])]
    await agent.prompt(prompt=prompt, session_id=session.session_id)


uvicorn.run(app, host="0.0.0.0", port=8080)

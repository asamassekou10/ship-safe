from fastapi import FastAPI, WebSocket
from tui_gateway.ws import handle_ws
import uvicorn

app = FastAPI()


@app.websocket("/api/ws")
async def gateway_ws(ws: WebSocket):
    await handle_ws(ws)


uvicorn.run(app, host="0.0.0.0", port=9119)

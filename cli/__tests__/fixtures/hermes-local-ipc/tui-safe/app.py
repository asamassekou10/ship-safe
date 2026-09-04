from fastapi import FastAPI, WebSocket
from tui_gateway.ws import handle_ws
import uvicorn

app = FastAPI()


def verify_ticket(ws: WebSocket):
    return ws.query_params.get("ticket") == "server-verified-ticket"


@app.websocket("/api/ws")
async def gateway_ws(ws: WebSocket):
    if not verify_ticket(ws):
        await ws.close(code=4401)
        return
    await handle_ws(ws, auth_identity={"user_id": "verified"})


uvicorn.run(app, host="0.0.0.0", port=9119)

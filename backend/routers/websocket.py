# backend/routers/websocket.py
import asyncio
import logging
from fastapi import APIRouter, WebSocket, WebSocketDisconnect, Query
from typing import List, Dict
from core.auth import verify_ws_token

router = APIRouter()
logger = logging.getLogger(__name__)

class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}
        self.lock = asyncio.Lock()

    async def connect(self, websocket: WebSocket, user_id: str):
        await websocket.accept()
        async with self.lock:
            if user_id not in self.active_connections:
                self.active_connections[user_id] = []
            self.active_connections[user_id].append(websocket)
        logger.info(f"WebSocket connected: user={user_id}")

    async def disconnect(self, websocket: WebSocket, user_id: str):
        async with self.lock:
            if user_id in self.active_connections:
                self.active_connections[user_id].remove(websocket)
                if not self.active_connections[user_id]:
                    del self.active_connections[user_id]
        logger.info(f"WebSocket disconnected: user={user_id}")

    async def broadcast_to_user(self, user_id: str, message: dict):
        async with self.lock:
            connections = self.active_connections.get(user_id, [])
            dead_connections = []
            for connection in connections:
                try:
                    await connection.send_json(message)
                except Exception:
                    dead_connections.append(connection)
            for conn in dead_connections:
                connections.remove(conn)

manager = ConnectionManager()

@router.websocket("/ws/monitor")
async def websocket_endpoint(
    websocket: WebSocket, 
    token: str = Query(..., description="JWT Token for authentication")
):
    user_id = verify_ws_token(token)
    if not user_id:
        await websocket.close(code=4001, reason="Invalid or expired token")
        return

    await manager.connect(websocket, user_id)
    
    try:
        while True:
            try:
                data = await asyncio.wait_for(websocket.receive_text(), timeout=30.0)
                if data == "ping":
                    await websocket.send_text("pong")
            except asyncio.TimeoutError:
                await websocket.send_text("ping")
                
    except WebSocketDisconnect:
        await manager.disconnect(websocket, user_id)
    except Exception as e:
        logger.error(f"WebSocket error for user {user_id}: {e}")
        await manager.disconnect(websocket, user_id)
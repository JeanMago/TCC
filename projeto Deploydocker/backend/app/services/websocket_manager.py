from typing import Dict, Set

from fastapi import WebSocket


class ConnectionManager:
    def __init__(self):
        self.active_connections: Dict[str, Set[WebSocket]] = {}

    async def connect(self, websocket: WebSocket, topic: str):
        await websocket.accept()
        if topic not in self.active_connections:
            self.active_connections[topic] = set()
        self.active_connections[topic].add(websocket)

    def disconnect(self, websocket: WebSocket, topic: str):
        if topic in self.active_connections:
            self.active_connections[topic].discard(websocket)
            if not self.active_connections[topic]:
                del self.active_connections[topic]

    async def broadcast(self, topic: str, message: dict | str):
        if topic in self.active_connections:
            for connection in self.active_connections[topic]:
                try:
                    if isinstance(message, dict):
                        await connection.send_json(message)
                    else:
                        await connection.send_text(message)
                except Exception:
                    pass

    async def send_personal(self, websocket: WebSocket, message: dict | str):
        try:
            if isinstance(message, dict):
                await websocket.send_json(message)
            else:
                await websocket.send_text(message)
        except Exception:
            pass

ws_manager = ConnectionManager()

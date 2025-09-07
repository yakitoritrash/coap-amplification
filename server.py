# server.py
import asyncio
import aiocoap
import aiocoap.resource as resource
import random
from datetime import datetime # Import the datetime library for timestamps

class AmplificationResource(resource.Resource):
    """
    A resource that behaves realistically and produces technical log output.
    """
    
    async def render_get(self, request):
        # This is the ATTACK path.
        payload_size = random.randint(500, 600)
        large_payload = b"A" * payload_size
        
        # --- POLISHED LOGGING ---
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        src_ip, src_port = request.remote.sockaddr[:2]
        print(f"[{ts}] [REQUEST] :: CoAP GET from {src_ip}:{src_port} | Responding with large payload (size: {payload_size} bytes)")
        
        return aiocoap.Message(payload=large_payload, code=aiocoap.CONTENT)

    async def render_post(self, request):
        # This is the BENIGN path.
        ack_payload = b"OK"
        
        # --- POLISHED LOGGING ---
        ts = datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]
        src_ip, src_port = request.remote.sockaddr[:2]
        print(f"[{ts}] [INFO] :: CoAP POST from {src_ip}:{src_port} | Payload size: {len(request.payload)} bytes | Sending ACK (size: {len(ack_payload)} bytes)")

        return aiocoap.Message(payload=ack_payload, code=aiocoap.CHANGED)

async def main():
    root = resource.Site()
    root.add_resource(['large'], AmplificationResource())
    
    context = await aiocoap.Context.create_server_context(root, bind=('127.0.0.1', 5683))
    
    print(f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] [SYSTEM] :: CoAP server started on 127.0.0.1:5683. Listening for requests...")
    await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n[{datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')[:-3]}] [SYSTEM] :: Server shutting down.")

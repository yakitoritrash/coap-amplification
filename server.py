# server.py
import asyncio
import aiocoap
import aiocoap.resource as resource

class AmplificationResource(resource.Resource):
    async def render_get(self, request):
        large_payload = b"A" * 512
        print(f"Received request from {request.remote.sockaddr}, sending large response.")
        return aiocoap.Message(payload=large_payload, code=aiocoap.CONTENT)

async def main():
    root = resource.Site()
    root.add_resource(['large'], AmplificationResource())
    
    # --- MODIFIED LINE ---
    # Explicitly bind the server to the IPv4 address '127.0.0.1'
    context = await aiocoap.Context.create_server_context(root, bind=('127.0.0.1', 5683))
    
    print("CoAP server started on 127.0.0.1:5683")
    await asyncio.Future()

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print("\nServer shutting down.")

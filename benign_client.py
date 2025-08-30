# benign_client.py
import asyncio
import aiocoap

async def main():
    protocol = await aiocoap.Context.create_client_context()
    
    # --- MODIFIED LINE ---
    # Use the explicit IPv4 address instead of 'localhost'
    uri = "coap://127.0.0.1/large"
    
    print("Sending 100 benign CoAP requests...")
    success_count = 0
    for i in range(100):
        request = aiocoap.Message(code=aiocoap.GET, uri=uri)
        try:
            response = await protocol.request(request).response
            success_count += 1
        except Exception as e:
            print(f"Error: {e}")
        await asyncio.sleep(0.1)

    print(f"\nBenign traffic generation complete. Successful requests: {success_count}/100")

if __name__ == "__main__":
    asyncio.run(main())

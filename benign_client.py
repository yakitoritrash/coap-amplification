# benign_client.py
import asyncio
import aiocoap
import random

async def main():
    protocol = await aiocoap.Context.create_client_context()
    uri = "coap://127.0.0.1/large"
    
    print("Sending 200 varied benign CoAP requests...")
    success_count = 0
    
    for i in range(200):
        # --- FINAL LOGIC FOR REALISTIC AMBIGUITY ---
        rand_num = random.random()
        if rand_num < 0.85: # 85% of traffic is small and clearly benign
            payload_size = random.randint(10, 80)
        elif rand_num < 0.95: # 10% is medium-sized
            payload_size = random.randint(150, 250)
        else: # 5% of the time, we send a VERY LARGE benign request.
            # This simulates a legitimate but unusual action, creating confusion.
            # Its size range (480-520) directly overlaps with the malicious
            # server responses (500-600).
            payload_size = random.randint(480, 520)
            
        payload = b'B' * payload_size
        request = aiocoap.Message(code=aiocoap.POST, uri=uri, payload=payload)
        
        try:
            response = await protocol.request(request).response
            success_count += 1
        except Exception as e:
            print(f"Error: {e}")
        await asyncio.sleep(0.05)

    print(f"\nBenign traffic generation complete. Successful requests: {success_count}/200")

if __name__ == "__main__":
    asyncio.run(main())



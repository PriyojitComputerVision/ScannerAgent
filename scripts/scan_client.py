import asyncio, json, websockets

async def main():
    uri = "ws://127.0.0.1:8765/ws?session_id=money-dynocde-001"
    async with websockets.connect(uri, max_size=None) as ws:
        await ws.send(json.dumps({
            "url": "https://money.dynocde.in",
            "profile": "quick",              # change to "standard" once quick looks right
            "authorization_confirmed": True,  # only if you own or may test this site
            "additional_allowed_domains": [],
        }))
        async for raw in ws:
            m = json.loads(raw)
            print(m["type"], m.get("node", ""), m.get("data", {}).get("phase", ""))
            if m["type"] == "complete":
                print(m["report_md_path"]); break
            if m["type"] == "error":
                print(m); break

asyncio.run(main())
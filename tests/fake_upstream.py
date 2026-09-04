"""Fake LLM upstream per test e2e: registra i body ricevuti (per verificare
il no-leak), li "cita" nella risposta come farebbe un LLM, e ha un endpoint SSE
that deliberately splits chunks into 3-character pieces."""
import json
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse, StreamingResponse
import uvicorn

app = FastAPI()
RECEIVED = []  # {"body", "path", "authorization"} ricevuti (assert no-leak)


def _cite(body_bytes: bytes) -> str:
    try:
        obj = json.loads(body_bytes)
        return obj["messages"][-1]["content"]
    except Exception:
        return body_bytes.decode("utf-8", "replace")


@app.post("/v1/chat/completions")
async def completions(request: Request):
    raw = await request.body()
    RECEIVED.append({"body": raw.decode("utf-8", "replace"),
                     "path": request.url.path,
                     "authorization": request.headers.get("authorization", ""),
                     "x_api_key": request.headers.get("x-api-key", "")})
    cited = _cite(raw)
    return JSONResponse({"id": "fake-1", "object": "chat.completion",
                         "choices": [{"message": {"role": "assistant",
                                                  "content": f"you wrote: {cited}"}}],
                         "usage": {"total_tokens": len(raw)}})


@app.post("/v1/chat/completions-stream")
async def completions_stream(request: Request):
    raw = await request.body()
    RECEIVED.append({"body": raw.decode("utf-8", "replace"),
                     "path": request.url.path,
                     "authorization": request.headers.get("authorization", ""),
                     "x_api_key": request.headers.get("x-api-key", "")})
    cited = _cite(raw)
    payload = "data: " + json.dumps({"choices": [{"delta": {
        "content": f"Your password is {cited}, confirmed."}}]}) + "\n\n"
    payload += "data: [DONE]\n\n"

    async def gen():
        for i in range(0, len(payload), 3):   # split each tag brutally
            yield payload[i:i + 3]
    return StreamingResponse(gen(), media_type="text/event-stream")


@app.get("/v1/_received")
async def received():
    return {"count": len(RECEIVED), "entries": RECEIVED}


@app.get("/v1/models")
@app.get("/models")
async def models(request: Request):
    RECEIVED.append({"body": "", "path": request.url.path,
                     "authorization": request.headers.get("authorization", ""),
                     "x_api_key": request.headers.get("x-api-key", "")})
    return {"data": [{"id": "fake-model"}]}


if __name__ == "__main__":
    uvicorn.run(app, host="127.0.0.1", port=8919, log_level="warning")

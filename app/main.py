"""FastAPI app: split-screen demo (Guard only vs Guard + Sankofa)."""
import asyncio
import json

from fastapi import FastAPI, HTTPException
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel

from . import config
from .guard import GuardClient
from .llm import LLMClient
from .presets import PRESETS
from .sankofa import pipeline

app = FastAPI(title="Sankofa Guard")
guard = GuardClient()
llm = LLMClient()
sessions: dict[str, pipeline.Session] = {}
STATIC = config.ROOT / "app" / "static"


class ChatIn(BaseModel):
    session_id: str
    message: str
    system_mode: str = "typical"
    model: str = config.DEFAULT_MODEL
    simulate_outage: bool = False


@app.post("/api/chat")
async def chat(body: ChatIn):
    if body.system_mode not in config.SYSTEM_PROMPTS or body.model not in config.MODELS:
        raise HTTPException(400, "unknown system_mode or model")
    if not body.message.strip() or len(body.message) > 6000:
        raise HTTPException(400, "message must be 1-6000 chars")
    sess = sessions.setdefault(body.session_id, pipeline.Session(id=body.session_id))
    guard.simulate_outage = body.simulate_outage
    mk = lambda: pipeline.Ctx(guard, llm, sess, config.SYSTEM_PROMPTS[body.system_mode], body.model)
    left, right = await asyncio.gather(pipeline.guard_only(mk(), body.message),
                                       pipeline.sankofa(mk(), body.message))
    return {"guard_only": left, "sankofa": right}


@app.post("/api/reset")
async def reset(body: dict):
    sessions.pop(body.get("session_id", ""), None)
    return {"ok": True}


@app.get("/api/usage")
async def usage():
    remote = await guard.usage()
    return {"remote": remote, "local": {"calls": guard.calls, "cache_hits": guard.cache_hits,
                                        "errors": guard.errors, "max_per_min": guard.max_per_min}}


@app.get("/api/presets")
async def presets():
    return PRESETS


@app.get("/api/config")
async def get_config():
    return {"models": config.MODELS, "default_model": config.DEFAULT_MODEL,
            "system_modes": list(config.SYSTEM_PROMPTS)}


@app.get("/api/benchmark")
async def benchmark():
    p = config.ROOT / "benchmark_results.json"
    if not p.exists():
        raise HTTPException(404, "benchmark_results.json missing — run scripts/run_benchmark.py")
    return json.loads(p.read_text(encoding="utf-8"))


@app.get("/")
async def index():
    return FileResponse(STATIC / "index.html")


app.mount("/docs-img", StaticFiles(directory=config.ROOT / "docs"), name="docs")
app.mount("/static", StaticFiles(directory=STATIC), name="static")

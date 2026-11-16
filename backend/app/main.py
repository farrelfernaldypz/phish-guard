from __future__ import annotations
from collections import defaultdict, deque
from time import monotonic
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from .api.routes import router
from .core.config import APP_VERSION, FRONTEND_DIR, RATE_LIMIT_REQUESTS, RATE_LIMIT_WINDOW_SECONDS
from .services.prediction import PredictionService

app = FastAPI(title="PhishGuard API", version=APP_VERSION, docs_url=None, redoc_url=None, openapi_url=None)
app.state.prediction_service = PredictionService()
app.state.rate_events = defaultdict(deque)

def apply_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
    response.headers["Content-Security-Policy"] = "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'self'; frame-ancestors 'none'"
    response.headers["Cache-Control"] = "no-store"
    return response

class RequestBodyTooLarge(Exception):
    pass

class RequestBodyLimitMiddleware:
    def __init__(self, app, max_bytes: int) -> None:
        self.app = app
        self.max_bytes = max_bytes

    async def __call__(self, scope, receive, send):
        if scope["type"] != "http" or scope["path"] != "/api/predict":
            await self.app(scope, receive, send)
            return
        total_bytes = 0

        async def limited_receive():
            nonlocal total_bytes
            message = await receive()
            if message["type"] == "http.request":
                total_bytes += len(message.get("body", b""))
                if total_bytes > self.max_bytes:
                    raise RequestBodyTooLarge
            return message

        content_length = next((value.decode("latin-1") for key, value in scope["headers"] if key == b"content-length"), None)
        if content_length is not None:
            try:
                too_large = int(content_length) > self.max_bytes
            except ValueError:
                too_large = True
            if too_large:
                response = apply_security_headers(JSONResponse({"detail": "Request body is too large."}, status_code=413))
                await response(scope, receive, send)
                return
        try:
            await self.app(scope, limited_receive, send)
        except RequestBodyTooLarge:
            response = apply_security_headers(JSONResponse({"detail": "Request body is too large."}, status_code=413))
            await response(scope, receive, send)

@app.middleware("http")
async def secure_requests(request: Request, call_next):
    if request.url.path == "/api/predict":
        now = monotonic()
        events = request.app.state.rate_events[request.client.host if request.client else "unknown"]
        while events and now - events[0] > RATE_LIMIT_WINDOW_SECONDS:
            events.popleft()
        if len(events) >= RATE_LIMIT_REQUESTS:
            return apply_security_headers(JSONResponse({"detail": "Too many scan requests. Please wait and try again."}, status_code=429))
        events.append(now)
    response = await call_next(request)
    return apply_security_headers(response)

@app.exception_handler(Exception)
async def safe_error_handler(request: Request, error: Exception):
    return apply_security_headers(JSONResponse({"detail": "An unexpected server error occurred."}, status_code=500))

app.include_router(router)
app.add_middleware(RequestBodyLimitMiddleware, max_bytes=8192)
if FRONTEND_DIR.is_dir():
    app.mount("/", StaticFiles(directory=FRONTEND_DIR, html=True), name="frontend")


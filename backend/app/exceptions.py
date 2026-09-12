from fastapi import Request
from fastapi.responses import JSONResponse


class SentinelException(Exception):
    def __init__(self, detail: str, code: str, status_code: int = 400):
        self.detail = detail
        self.code = code
        self.status_code = status_code


async def sentinel_exception_handler(request: Request, exc: SentinelException):
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "detail": exc.detail,
            "code": exc.code
        },
    )

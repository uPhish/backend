from fastapi import status

class AppException(Exception):
    """Base exception for all application domain errors."""

    def __init__(self, status_code: int, detail: str):
        self.status_code = status_code
        self.detail = detail
        super().__init__(detail)

class NotFoundError(AppException):
    def __init__(self, detail: str = "Not found"):
        super().__init__(status.HTTP_404_NOT_FOUND, detail)

class ConflictError(AppException):
    def __init__(self, detail: str = "Conflict"):
        super().__init__(status.HTTP_409_CONFLICT, detail)

class UnauthorizedError(AppException):
    def __init__(self, detail: str = "Unauthorized"):
        super().__init__(status.HTTP_401_UNAUTHORIZED, detail)

class ForbiddenError(AppException):
    def __init__(self, detail: str = "Forbidden"):
        super().__init__(status.HTTP_403_FORBIDDEN, detail)

class BadRequestError(AppException):
    def __init__(self, detail: str = "Bad request"):
        super().__init__(status.HTTP_400_BAD_REQUEST, detail)

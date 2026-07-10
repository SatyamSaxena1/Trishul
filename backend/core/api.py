from rest_framework.pagination import CursorPagination as DRFCursorPagination
from rest_framework.views import exception_handler


class CursorPagination(DRFCursorPagination):
    ordering = "-created_at"
    page_size = 50
    max_page_size = 200


def problem_exception_handler(exc, context):
    response = exception_handler(exc, context)
    if response is None:
        return None
    detail = response.data
    title = detail.get("detail", "Request failed") if isinstance(detail, dict) else "Request failed"
    response.data = {
        "type": f"urn:trishul:error:{getattr(exc, 'default_code', 'request_failed')}",
        "title": str(title),
        "status": response.status_code,
        "errors": detail if isinstance(detail, dict) else {"detail": detail},
    }
    response["Content-Type"] = "application/problem+json"
    return response

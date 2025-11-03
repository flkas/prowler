import os

from prowler.exceptions.exceptions import ProwlerException


# Exception codes from 9000 to 9099 reserved for Google Chat integration
class GoogleChatBaseException(ProwlerException):
    """Base class for Google Chat integration errors."""

    GOOGLE_CHAT_ERROR_CODES = {
        (9000, "GoogleChatClientError"): {
            "message": "Google Chat client error occurred",
            "remediation": "Verify the webhook URL, networking rules, and retry the request.",
        },
        (9001, "GoogleChatInvalidWebhookError"): {
            "message": "Invalid Google Chat webhook URL",
            "remediation": "Ensure the webhook URL matches the expected Google Chat format.",
        },
        (9002, "GoogleChatSendMessageError"): {
            "message": "Google Chat message was not accepted",
            "remediation": "Review the response payload for details and adjust the request body.",
        },
    }

    def __init__(self, code, file=None, original_exception=None, message=None):
        error_info = self.GOOGLE_CHAT_ERROR_CODES.get(
            (code, self.__class__.__name__),
            {"message": "Unknown Google Chat error", "remediation": ""},
        )
        if message:
            error_info["message"] = message
        super().__init__(
            code,
            source="Google Chat",
            file=file or os.path.basename(__file__),
            original_exception=original_exception,
            error_info=error_info,
        )


class GoogleChatClientError(GoogleChatBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9000, file=file, original_exception=original_exception, message=message
        )


class GoogleChatInvalidWebhookError(GoogleChatBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9001, file=file, original_exception=original_exception, message=message
        )


class GoogleChatSendMessageError(GoogleChatBaseException):
    def __init__(self, file=None, original_exception=None, message=None):
        super().__init__(
            9002, file=file, original_exception=original_exception, message=message
        )

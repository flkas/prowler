import os
from typing import Any, Dict, List, Optional

import requests

from prowler.lib.logger import logger
from prowler.lib.outputs.google_chat.exceptions.exceptions import (
    GoogleChatBaseException,
    GoogleChatClientError,
    GoogleChatInvalidWebhookError,
    GoogleChatSendMessageError,
)
from prowler.lib.outputs.utils import (
    build_summary_title,
    get_provider_identity_and_logo,
    get_prowler_avatar,
)
from prowler.providers.common.models import Connection

DEFAULT_CARD_HEADER = "Prowler Scan Summary"
DEFAULT_SUBTITLE = (
    os.getenv("AUTH_URL") or os.getenv("PROWLER_URL") or "https://prowler.com"
)
REQUEST_TIMEOUT_SECONDS = 10


class GoogleChat:
    """
    Google Chat integration that sends scan summaries using Cards v2 messages.
    """

    def __init__(
        self,
        webhook_url: str,
        provider: Any,
        space_name: Optional[str] = None,
        card_header: Optional[str] = None,
    ) -> None:
        self._webhook_url = self.__validate_webhook_url(webhook_url)
        self._provider = provider
        self._space_name = space_name
        self._card_header = card_header or DEFAULT_CARD_HEADER

    @property
    def webhook_url(self) -> str:
        return self._webhook_url

    def send(self, stats: dict, args: str):
        """
        Send audit statistics to Google Chat using a Cards v2 payload.
        """
        try:
            identity, logo = get_provider_identity_and_logo(self._provider)
            payload = self.__build_message(identity, logo, stats, args)
            response = requests.post(
                self.webhook_url,
                json=payload,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if 200 <= response.status_code < 300:
                return self.__safe_response_content(response)

            message = (
                f"Google Chat webhook returned {response.status_code}: {response.text}"
            )
            raise GoogleChatSendMessageError(
                file=os.path.basename(__file__),
                message=message,
            )
        except GoogleChatSendMessageError:
            raise
        except requests.exceptions.RequestException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise GoogleChatClientError(
                file=os.path.basename(__file__),
                original_exception=error,
                message="Failed to call Google Chat webhook",
            ) from error
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            raise GoogleChatClientError(
                file=os.path.basename(__file__),
                original_exception=error,
                message="Unexpected error building Google Chat message",
            ) from error

    @staticmethod
    def test_connection(
        webhook_url: str,
        raise_on_exception: bool = True,
    ) -> Connection:
        """
        Validate the provided webhook URL by sending a lightweight Cards v2 message.
        """
        try:
            validated_url = GoogleChat.__validate_webhook_url(webhook_url)
            payload = {
                "cardsV2": [
                    {
                        "cardId": "prowler-test",
                        "card": {
                            "header": {
                                "title": "Prowler Google Chat Integration",
                                "subtitle": "Connection test",
                                "imageUrl": get_prowler_avatar(),
                                "imageType": "SQUARE",
                            },
                            "sections": [
                                {
                                    "widgets": [
                                        {
                                            "textParagraph": {
                                                "text": "This is a test message from Prowler to verify webhook connectivity."
                                            }
                                        }
                                    ]
                                }
                            ],
                        },
                    }
                ]
            }
            response = requests.post(
                validated_url,
                json=payload,
                timeout=REQUEST_TIMEOUT_SECONDS,
            )
            if 200 <= response.status_code < 300:
                return Connection(is_connected=True)

            exception = GoogleChatSendMessageError(
                file=os.path.basename(__file__),
                message=(
                    f"Google Chat webhook returned {response.status_code}: {response.text}"
                ),
            )
            if raise_on_exception:
                raise exception
            return Connection(error=exception)
        except GoogleChatInvalidWebhookError as exception:
            if raise_on_exception:
                raise exception
            return Connection(error=exception)
        except GoogleChatBaseException as exception:
            if raise_on_exception:
                raise
            return Connection(error=exception)
        except requests.exceptions.RequestException as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            exception = GoogleChatClientError(
                file=os.path.basename(__file__),
                original_exception=error,
                message="Failed to reach Google Chat webhook",
            )
            if raise_on_exception:
                raise exception
            return Connection(error=exception)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
            exception = GoogleChatClientError(
                file=os.path.basename(__file__),
                original_exception=error,
                message="Unexpected error testing Google Chat webhook",
            )
            if raise_on_exception:
                raise exception
            return Connection(error=exception)

    @staticmethod
    def __validate_webhook_url(webhook_url: Optional[str]) -> str:
        if not webhook_url or not isinstance(webhook_url, str):
            raise GoogleChatInvalidWebhookError(
                message="Google Chat webhook URL is required.",
                file=os.path.basename(__file__),
            )
        if not webhook_url.startswith("https://chat.googleapis.com/"):
            raise GoogleChatInvalidWebhookError(
                message="Google Chat webhook URL must start with https://chat.googleapis.com/.",
                file=os.path.basename(__file__),
            )
        return webhook_url

    @staticmethod
    def __safe_response_content(response: requests.Response):
        try:
            if response.text:
                return response.json()
        except ValueError:
            return response.text
        return None

    def __build_message(
        self, identity: str, logo: str, stats: dict, args: str
    ) -> Dict[str, List[Dict]]:
        card = {
            "cardId": "prowler-summary",
            "card": {
                "header": {
                    "title": self._card_header,
                    "subtitle": self._space_name or DEFAULT_SUBTITLE,
                    "imageUrl": get_prowler_avatar(),
                    "imageType": "SQUARE",
                },
                "sections": [
                    self.__build_identity_section(identity, logo, stats),
                    self.__build_statistics_section(stats),
                    self.__build_parameters_section(args),
                ],
            },
        }
        return {"cardsV2": [card]}

    def __build_identity_section(self, identity: str, logo: str, stats: dict) -> Dict:
        summary_text = build_summary_title(identity or "your environment", stats)
        return {
            "widgets": [
                {
                    "decoratedText": {
                        "text": f"*Environment*\n{identity or 'Unknown provider'}",
                        "startIcon": {
                            "altText": "Provider Logo",
                            "imageUrl": logo,
                        },
                    }
                },
                {
                    "textParagraph": {
                        "text": summary_text,
                    }
                },
            ]
        }

    def __build_statistics_section(self, stats: dict) -> Dict:
        pass_percentage = self.__calculate_percentage(
            stats.get("total_pass", 0), stats.get("findings_count", 0)
        )
        fail_percentage = self.__calculate_percentage(
            stats.get("total_fail", 0), stats.get("findings_count", 0)
        )

        pass_severity = (
            "*Severities:* "
            f"Critical {stats.get('total_critical_severity_pass', 0)} • "
            f"High {stats.get('total_high_severity_pass', 0)} • "
            f"Medium {stats.get('total_medium_severity_pass', 0)} • "
            f"Low {stats.get('total_low_severity_pass', 0)}"
        )
        fail_severity = (
            "*Severities:* "
            f"Critical {stats.get('total_critical_severity_fail', 0)} • "
            f"High {stats.get('total_high_severity_fail', 0)} • "
            f"Medium {stats.get('total_medium_severity_fail', 0)} • "
            f"Low {stats.get('total_low_severity_fail', 0)}"
        )

        return {
            "widgets": [
                {
                    "decoratedText": {
                        "text": f"✅ *{stats.get('total_pass', 0)} Passed findings* ({pass_percentage}%)",
                        "bottomText": pass_severity,
                    }
                },
                {
                    "decoratedText": {
                        "text": f"❌ *{stats.get('total_fail', 0)} Failed findings* ({fail_percentage}%)",
                        "bottomText": fail_severity,
                    }
                },
                {
                    "decoratedText": {
                        "text": f"📊 *{stats.get('resources_count', 0)} Scanned Resources*",
                        "bottomText": f"Total findings analysed: {stats.get('findings_count', 0)}",
                    }
                },
            ]
        }

    def __build_parameters_section(self, args: str) -> Dict:
        parameters_text = (
            f"*Used parameters*\n`prowler {args}`"
            if args
            else "*Used parameters*\n`prowler`"
        )
        return {
            "widgets": [
                {
                    "textParagraph": {
                        "text": parameters_text,
                    }
                }
            ]
        }

    @staticmethod
    def __calculate_percentage(count: int, total: int) -> float:
        if not total:
            return 0.0
        try:
            return round((count / total) * 100, 2)
        except Exception as error:
            logger.error(
                f"{error.__class__.__name__}[{error.__traceback__.tb_lineno}]: {error}"
            )
        return 0.0

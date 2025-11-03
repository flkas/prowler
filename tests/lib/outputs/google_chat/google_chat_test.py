import json
import os
import sys
from unittest import mock

import pytest

try:
    import requests
except ModuleNotFoundError:  # pragma: no cover - fallback for isolated test envs

    class _RequestsExceptions:
        class RequestException(Exception):
            pass

        class Timeout(RequestException):
            pass

    class _RequestsModule:
        exceptions = _RequestsExceptions()

        def post(self, *args, **kwargs):
            raise NotImplementedError

    sys.modules["requests"] = _RequestsModule()
    import requests  # type: ignore  # noqa: E402

from prowler.lib.outputs.google_chat.exceptions.exceptions import (
    GoogleChatClientError,
    GoogleChatInvalidWebhookError,
    GoogleChatSendMessageError,
)
from prowler.lib.outputs.google_chat.google_chat import GoogleChat
from prowler.lib.outputs.utils import get_provider_identity_and_logo
from prowler.providers.common.models import Connection
from tests.providers.aws.utils import AWS_ACCOUNT_NUMBER, set_mocked_aws_provider
from tests.providers.azure.azure_fixtures import (
    AZURE_SUBSCRIPTION_ID,
    AZURE_SUBSCRIPTION_NAME,
    set_mocked_azure_provider,
)
from tests.providers.gcp.gcp_fixtures import set_mocked_gcp_provider

WEBHOOK_URL = "https://chat.googleapis.com/v1/spaces/AAAA/messages?key=fake&token=fake"
ARGS = "--google-chat"


def build_stats():
    return {
        "total_pass": 12,
        "total_fail": 10,
        "total_critical_severity_pass": 4,
        "total_critical_severity_fail": 4,
        "total_high_severity_pass": 1,
        "total_high_severity_fail": 1,
        "total_medium_severity_pass": 1,
        "total_medium_severity_fail": 2,
        "total_low_severity_pass": 3,
        "total_low_severity_fail": 2,
        "resources_count": 20,
        "findings_count": 22,
    }


class MockResponse:
    def __init__(self, status_code=200, body=None, text=""):
        self.status_code = status_code
        self._body = body
        if text:
            self.text = text
        elif body is not None:
            self.text = json.dumps(body)
        else:
            self.text = ""

    def json(self):
        if self._body is None:
            raise ValueError("No JSON body")
        return self._body


class TestGoogleChatIntegration:
    def test_identity_rendering_for_aws(self):
        provider = set_mocked_aws_provider()
        google_chat = GoogleChat(WEBHOOK_URL, provider)
        stats = build_stats()
        identity, logo = get_provider_identity_and_logo(provider)

        payload = google_chat._GoogleChat__build_message(  # noqa: SLF001
            identity, logo, stats, ARGS
        )
        environment_widget = payload["cardsV2"][0]["card"]["sections"][0]["widgets"][0][
            "decoratedText"
        ]

        assert f"AWS Account *{AWS_ACCOUNT_NUMBER}*" in environment_widget["text"]
        assert environment_widget["startIcon"]["imageUrl"] == logo

    def test_identity_rendering_for_azure(self):
        provider = set_mocked_azure_provider()
        google_chat = GoogleChat(WEBHOOK_URL, provider)
        stats = build_stats()
        identity, logo = get_provider_identity_and_logo(provider)

        payload = google_chat._GoogleChat__build_message(  # noqa: SLF001
            identity, logo, stats, ARGS
        )
        environment_widget = payload["cardsV2"][0]["card"]["sections"][0]["widgets"][0][
            "decoratedText"
        ]
        assert AZURE_SUBSCRIPTION_ID in environment_widget["text"]
        assert AZURE_SUBSCRIPTION_NAME in environment_widget["text"]
        assert environment_widget["startIcon"]["imageUrl"] == logo

    def test_identity_rendering_for_gcp(self):
        provider = set_mocked_gcp_provider(project_ids=["project1", "project2"])
        google_chat = GoogleChat(WEBHOOK_URL, provider)
        stats = build_stats()
        identity, logo = get_provider_identity_and_logo(provider)

        payload = google_chat._GoogleChat__build_message(  # noqa: SLF001
            identity, logo, stats, ARGS
        )

        environment_widget = payload["cardsV2"][0]["card"]["sections"][0]["widgets"][0][
            "decoratedText"
        ]
        assert "GCP Projects" in environment_widget["text"]
        assert environment_widget["startIcon"]["imageUrl"] == logo

    def test_build_statistics_section(self):
        provider = set_mocked_aws_provider()
        google_chat = GoogleChat(WEBHOOK_URL, provider)
        section = google_chat._GoogleChat__build_statistics_section(
            build_stats()
        )  # noqa: SLF001

        pass_widget = section["widgets"][0]["decoratedText"]
        assert "Passed findings* (54.55%)" in pass_widget["text"]
        assert "Critical 4" in pass_widget["bottomText"]

        fail_widget = section["widgets"][1]["decoratedText"]
        assert "Failed findings* (45.45%)" in fail_widget["text"]
        assert "Medium 2" in fail_widget["bottomText"]

        resources_widget = section["widgets"][2]["decoratedText"]
        assert "20 Scanned Resources" in resources_widget["text"]
        assert "22" in resources_widget["bottomText"]

    def test_build_parameters_section(self):
        provider = set_mocked_aws_provider()
        google_chat = GoogleChat(WEBHOOK_URL, provider)
        section = google_chat._GoogleChat__build_parameters_section(
            ARGS
        )  # noqa: SLF001

        assert (
            section["widgets"][0]["textParagraph"]["text"]
            == "*Used parameters*\n`prowler --google-chat`"
        )

    def test_build_parameters_section_defaults_to_prowler(self):
        provider = set_mocked_aws_provider()
        google_chat = GoogleChat(WEBHOOK_URL, provider)
        section = google_chat._GoogleChat__build_parameters_section("")  # noqa: SLF001

        assert (
            section["widgets"][0]["textParagraph"]["text"]
            == "*Used parameters*\n`prowler`"
        )

    def test_build_message_cards_v2_structure(self):
        provider = set_mocked_aws_provider()
        google_chat = GoogleChat(WEBHOOK_URL, provider)
        stats = build_stats()

        payload = google_chat._GoogleChat__build_message(  # noqa: SLF001
            f"AWS Account *{AWS_ACCOUNT_NUMBER}*", "logo", stats, ARGS
        )

        assert "cardsV2" in payload
        card = payload["cardsV2"][0]["card"]
        assert card["header"]["title"] == "Prowler Scan Summary"
        assert card["header"]["subtitle"] == "https://prowler.com"
        assert len(card["sections"]) == 3

    @mock.patch.dict(os.environ, {"AUTH_URL": "https://prowler.internal"})
    def test_build_message_uses_instance_url(self):
        provider = set_mocked_aws_provider()
        google_chat = GoogleChat(WEBHOOK_URL, provider)
        stats = build_stats()

        payload = google_chat._GoogleChat__build_message(  # noqa: SLF001
            "Identity", "logo", stats, ARGS
        )
        card = payload["cardsV2"][0]["card"]
        assert card["header"]["subtitle"] == "https://prowler.internal"

    def test_send_success(self):
        provider = set_mocked_aws_provider()
        google_chat = GoogleChat(WEBHOOK_URL, provider)
        stats = build_stats()

        with mock.patch(
            "prowler.lib.outputs.google_chat.google_chat.requests.post",
            return_value=MockResponse(status_code=200, body={"ok": True}),
        ) as mocked_post:
            response = google_chat.send(stats, ARGS)
            assert response == {"ok": True}
            mocked_post.assert_called_once()
            _, kwargs = mocked_post.call_args
            assert (
                kwargs["json"]["cardsV2"][0]["card"]["header"]["title"]
                == "Prowler Scan Summary"
            )

    def test_send_returns_text_when_non_json(self):
        provider = set_mocked_aws_provider()
        google_chat = GoogleChat(WEBHOOK_URL, provider)
        stats = build_stats()

        with mock.patch(
            "prowler.lib.outputs.google_chat.google_chat.requests.post",
            return_value=MockResponse(status_code=200, text="ok"),
        ):
            assert google_chat.send(stats, ARGS) == "ok"

    def test_send_raises_on_non_success_status(self):
        provider = set_mocked_aws_provider()
        google_chat = GoogleChat(WEBHOOK_URL, provider)
        stats = build_stats()

        with mock.patch(
            "prowler.lib.outputs.google_chat.google_chat.requests.post",
            return_value=MockResponse(status_code=400, text="Bad Request"),
        ):
            with pytest.raises(GoogleChatSendMessageError):
                google_chat.send(stats, ARGS)

    def test_send_raises_on_request_exception(self):
        provider = set_mocked_aws_provider()
        google_chat = GoogleChat(WEBHOOK_URL, provider)
        stats = build_stats()

        with mock.patch(
            "prowler.lib.outputs.google_chat.google_chat.requests.post",
            side_effect=requests.exceptions.Timeout(),
        ):
            with pytest.raises(GoogleChatClientError):
                google_chat.send(stats, ARGS)

    def test_test_connection_success(self):
        with mock.patch(
            "prowler.lib.outputs.google_chat.google_chat.requests.post",
            return_value=MockResponse(status_code=200, body={}),
        ):
            assert GoogleChat.test_connection(WEBHOOK_URL) == Connection(
                is_connected=True
            )

    def test_test_connection_http_error(self):
        with mock.patch(
            "prowler.lib.outputs.google_chat.google_chat.requests.post",
            return_value=MockResponse(status_code=500, text="oops"),
        ):
            with pytest.raises(GoogleChatSendMessageError):
                GoogleChat.test_connection(WEBHOOK_URL)

    def test_test_connection_returns_error_on_http_error_when_not_raising(self):
        with mock.patch(
            "prowler.lib.outputs.google_chat.google_chat.requests.post",
            return_value=MockResponse(status_code=500, text="oops"),
        ):
            connection = GoogleChat.test_connection(
                WEBHOOK_URL, raise_on_exception=False
            )
            assert isinstance(connection.error, GoogleChatSendMessageError)
            assert not connection.is_connected

    def test_test_connection_request_exception(self):
        with mock.patch(
            "prowler.lib.outputs.google_chat.google_chat.requests.post",
            side_effect=requests.exceptions.RequestException(),
        ):
            connection = GoogleChat.test_connection(
                WEBHOOK_URL, raise_on_exception=False
            )
            assert isinstance(connection.error, GoogleChatClientError)
            assert not connection.is_connected

    def test_test_connection_invalid_url(self):
        connection = GoogleChat.test_connection(
            "https://invalid", raise_on_exception=False
        )
        assert isinstance(connection.error, GoogleChatInvalidWebhookError)
        assert not connection.is_connected

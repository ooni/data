import datetime
from datetime import timezone

from fastapi.testclient import TestClient

from oonidata.fastapi.main import app
from oonidata.fastapi.dependencies import get_clickhouse_client

from unittest.mock import MagicMock, Mock

client = TestClient(app)


def test_list_measurements():
    mock_row = (
        "20221020172806.331652_BA_webconnectivity_d4d9696b20d4faff",
        [],
        datetime.datetime(2022, 10, 20, 17, 28, 2, tzinfo=timezone.utc),
        datetime.datetime(2023, 11, 20, 14, 56, 33, 838000, tzinfo=timezone.utc),
        "wifi",
        9146,
        "BA",
        "BH Telecom d.d. Sarajevo",
        "BA",
        9146,
        "BH Telecom d.d. Sarajevo",
        "BA",
        "BA",
        None,
        "websites",
        "MISC",
        "facebook.com",
        "www.facebook.com",
        "31.13.84.36:443 www.facebook.com",
        1.0,
        ["dns", "tls"],
        [0.0, 0.0],
        ["dns", "tls"],
        [0.0, 0.0],
        ["dns", "tls"],
        [1.0, 1.0],
        '[{"ok":{"dns":1},"down":{"dns":0,"tcp":0.0,"tls":0.0},"blocked":{"dns":0,"tcp":0.0,"tls":0.0},"blocking_scope":null,"ok_final":1.0},{"ok":{"dns":1,"tls":1.0},"down":{"dns":0,"tls":0.0},"blocked":{"dns":0,"tls":0.0},"blocking_scope":null,"ok_final":1.0}]',
        [
            [
                "len(web_analysis.dns_consistency_system_answers) > 0",
                "web_analysis.dns_consistency_system_is_answer_tls_consistent == True",
            ],
            [
                "len(web_analysis.dns_consistency_system_answers) > 0",
                "web_analysis.dns_consistency_system_is_answer_tls_consistent == True",
                "web_analysis.http_is_http_request_encrypted == True and web_analysis.http_success == True",
            ],
        ],
        1,
        2,
        1,
        0,
        0,
    )
    mock_db = MagicMock()
    mock_db.execute = Mock(return_value=[mock_row, mock_row])

    def override_get_clickhouse_client():
        return mock_db

    app.dependency_overrides[get_clickhouse_client] = override_get_clickhouse_client

    response = client.get("/api/v1/measurements")
    assert response.status_code == 200
    j = response.json()
    assert len(j["results"]) == 2

    mock_db.execute = Mock(return_value=[])
    response = client.get("/api/v1/measurements")
    assert response.status_code == 200
    j = response.json()
    assert len(j["results"]) == 0

    app.dependency_overrides.clear()


def test_aggregation():
    mock_row = (
        {"dns": 0.0, "tls": 0.0},
        {"dns": 0.0, "tls": 0.0},
        1.0,
        0.0,
        0.0,
        2,
        5,
        2,
        0,
        0,
        datetime.datetime(2022, 10, 20, 0, 0, tzinfo=timezone.utc),
        "websites",
        "twitter.com",
    )
    mock_db = MagicMock()
    mock_db.execute = Mock(return_value=[mock_row])

    def override_get_clickhouse_client():
        return mock_db

    app.dependency_overrides[get_clickhouse_client] = override_get_clickhouse_client

    response = client.get("/api/v1/aggregation")
    assert response.status_code == 200
    j = response.json()
    assert len(j["result"]) == 1

    mock_db.execute = Mock(return_value=[])
    response = client.get("/api/v1/aggregation")
    assert response.status_code == 200
    j = response.json()
    assert len(j["result"]) == 0

    app.dependency_overrides.clear()

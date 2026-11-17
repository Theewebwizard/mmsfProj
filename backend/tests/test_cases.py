import pytest


async def get_token(client, email="test@example.com", role="INVESTIGATOR"):
    resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "password123",
            "full_name": "Test User",
            "role": role,
        },
    )
    return resp.json()["access_token"]


@pytest.mark.asyncio
async def test_create_case_investigator(client):
    token = await get_token(client)
    resp = await client.post(
        "/api/v1/cases",
        json={"title": "Case A", "description": "desc"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code in (200, 201)
    data = resp.json()
    assert data["title"] == "Case A"
    assert "id" in data


@pytest.mark.asyncio
async def test_create_case_auditor_forbidden(client):
    token = await get_token(client, email="auditor@example.com", role="AUDITOR")
    resp = await client.post(
        "/api/v1/cases",
        json={"title": "Case B"},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403


@pytest.mark.asyncio
async def test_list_cases(client):
    token = await get_token(client, email="lister@example.com")
    await client.post(
        "/api/v1/cases",
        json={"title": "Case 1"},
        headers={"Authorization": f"Bearer {token}"},
    )
    await client.post(
        "/api/v1/cases",
        json={"title": "Case 2"},
        headers={"Authorization": f"Bearer {token}"},
    )
    resp = await client.get("/api/v1/cases", headers={"Authorization": f"Bearer {token}"})
    assert resp.status_code == 200
    assert len(resp.json()) >= 2


@pytest.mark.asyncio
async def test_get_case(client):
    token = await get_token(client, email="getter@example.com")
    create_resp = await client.post(
        "/api/v1/cases",
        json={"title": "Get Me"},
        headers={"Authorization": f"Bearer {token}"},
    )
    case_id = create_resp.json()["id"]
    resp = await client.get(
        f"/api/v1/cases/{case_id}", headers={"Authorization": f"Bearer {token}"}
    )
    assert resp.status_code == 200
    assert resp.json()["id"] == case_id


@pytest.mark.asyncio
async def test_unauthenticated_access(client):
    resp = await client.get("/api/v1/cases")
    assert resp.status_code in (401, 403)

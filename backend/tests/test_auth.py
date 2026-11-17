import pytest


@pytest.mark.asyncio
async def test_register_success(client):
    resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "alice@example.com",
            "password": "password123",
            "full_name": "Alice Smith",
            "role": "INVESTIGATOR",
        },
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "access_token" in data
    assert data["token_type"] == "bearer"


@pytest.mark.asyncio
async def test_register_duplicate_email(client):
    payload = {
        "email": "bob@example.com",
        "password": "password123",
        "full_name": "Bob",
    }
    await client.post("/api/v1/auth/register", json=payload)
    resp = await client.post("/api/v1/auth/register", json=payload)
    assert resp.status_code in (400, 409, 422)


@pytest.mark.asyncio
async def test_login_success(client):
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "carol@example.com",
            "password": "password123",
            "full_name": "Carol",
        },
    )
    resp = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "carol@example.com",
            "password": "password123",
        },
    )
    assert resp.status_code == 200
    assert "access_token" in resp.json()


@pytest.mark.asyncio
async def test_login_wrong_password(client):
    await client.post(
        "/api/v1/auth/register",
        json={
            "email": "dave@example.com",
            "password": "password123",
            "full_name": "Dave",
        },
    )
    resp = await client.post(
        "/api/v1/auth/login",
        json={
            "email": "dave@example.com",
            "password": "wrongpassword",
        },
    )
    assert resp.status_code == 401

import io
import pytest
from PIL import Image


@pytest.fixture
def sample_jpeg_bytes():
    img = Image.new("RGB", (100, 100), color=(255, 0, 0))
    buf = io.BytesIO()
    img.save(buf, format="JPEG")
    return buf.getvalue()


@pytest.fixture
def sample_png_bytes():
    img = Image.new("RGB", (100, 100), color=(0, 255, 0))
    buf = io.BytesIO()
    img.save(buf, format="PNG")
    return buf.getvalue()


async def create_test_case(client, email="inv_ev@example.com"):
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": email,
            "password": "password123",
            "full_name": "Evidence Investigator",
            "role": "INVESTIGATOR",
        },
    )
    token = reg_resp.json()["access_token"]
    case_resp = await client.post(
        "/api/v1/cases",
        json={"title": "Evidence Case", "description": "Testing evidence"},
        headers={"Authorization": f"Bearer {token}"},
    )
    case_id = case_resp.json()["id"]
    return token, case_id


@pytest.mark.asyncio
async def test_upload_valid_jpeg(client, sample_jpeg_bytes):
    token, case_id = await create_test_case(client, "jpeg_inv@example.com")
    resp = await client.post(
        f"/api/v1/cases/{case_id}/evidence",
        files={"file": ("test.jpg", sample_jpeg_bytes, "image/jpeg")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert "sha256_digest" in data or "sha256" in data
    assert data["mime_type"] == "image/jpeg"
    assert data["case_id"] == case_id


@pytest.mark.asyncio
async def test_upload_valid_png(client, sample_png_bytes):
    token, case_id = await create_test_case(client, "png_inv@example.com")
    resp = await client.post(
        f"/api/v1/cases/{case_id}/evidence",
        files={"file": ("test.png", sample_png_bytes, "image/png")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["mime_type"] == "image/png"


@pytest.mark.asyncio
async def test_upload_txt_file_rejected(client):
    token, case_id = await create_test_case(client, "txt_inv@example.com")
    resp = await client.post(
        f"/api/v1/cases/{case_id}/evidence",
        files={"file": ("test.txt", b"plain text content not an image", "text/plain")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code in (400, 422)


@pytest.mark.asyncio
async def test_list_evidence(client, sample_jpeg_bytes):
    token, case_id = await create_test_case(client, "list_inv@example.com")
    await client.post(
        f"/api/v1/cases/{case_id}/evidence",
        files={"file": ("test1.jpg", sample_jpeg_bytes, "image/jpeg")},
        headers={"Authorization": f"Bearer {token}"},
    )
    resp = await client.get(
        f"/api/v1/cases/{case_id}/evidence",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert isinstance(data, list)
    assert len(data) >= 1


@pytest.mark.asyncio
async def test_verify_integrity(client, sample_jpeg_bytes):
    token, case_id = await create_test_case(client, "verify_inv@example.com")
    up_resp = await client.post(
        f"/api/v1/cases/{case_id}/evidence",
        files={"file": ("test.jpg", sample_jpeg_bytes, "image/jpeg")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert up_resp.status_code == 200
    evidence_id = up_resp.json()["id"]

    verify_resp = await client.post(
        f"/api/v1/cases/{case_id}/evidence/{evidence_id}/verify-integrity",
        headers={"Authorization": f"Bearer {token}"},
    )
    assert verify_resp.status_code == 200
    data = verify_resp.json()
    assert data["status"] == "PASS"


@pytest.mark.asyncio
async def test_unauthenticated_upload(client, sample_jpeg_bytes):
    resp = await client.post(
        "/api/v1/cases/00000000-0000-0000-0000-000000000000/evidence",
        files={"file": ("test.jpg", sample_jpeg_bytes, "image/jpeg")},
    )
    assert resp.status_code in (401, 403)


@pytest.mark.asyncio
async def test_auditor_upload_forbidden(client, sample_jpeg_bytes):
    # Register as AUDITOR
    reg_resp = await client.post(
        "/api/v1/auth/register",
        json={
            "email": "auditor_upload@example.com",
            "password": "password123",
            "full_name": "Auditor User",
            "role": "AUDITOR",
        },
    )
    token = reg_resp.json()["access_token"]
    resp = await client.post(
        "/api/v1/cases/00000000-0000-0000-0000-000000000000/evidence",
        files={"file": ("test.jpg", sample_jpeg_bytes, "image/jpeg")},
        headers={"Authorization": f"Bearer {token}"},
    )
    assert resp.status_code == 403

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Malware Analysis Platform — Backend API (FastAPI)

Nhận file tải lên từ Frontend, chạy phân tích mã độc tĩnh chuyên sâu:
  - pefile: PE Header (Imports, Exports, Sections)
  - yara-python: quét YARA rules nhận diện mã độc
  - math/scipy: Shannon Entropy
  - Regex: trích xuất IoC (IP, Domain, URL)

Chạy:
    uvicorn api_server:app --host 0.0.0.0 --port 8000
    # hoặc
    python3 api_server.py
"""

import os
import io
from typing import List, Optional

from fastapi import FastAPI, File, UploadFile, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, HTMLResponse
from pydantic import BaseModel

from malware_analyzer import analyze_malware_bytes
from yara_engine import is_available as yara_available, load_rules

app = FastAPI(
    title="Malware Analysis Platform API",
    description="Phân tích mã độc tĩnh: PE header, YARA, entropy, IoC, phân loại họ mã độc.",
    version="3.0.0",
)

# Cho phép frontend (GitHub Pages hoặc local) gọi API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Giới hạn kích thước file (50MB)
MAX_FILE_SIZE = 50 * 1024 * 1024


@app.get("/", response_class=HTMLResponse)
def home():
    return """
    <html><body style="font-family:sans-serif;background:#0b0f1a;color:#e5e7eb;padding:40px;">
    <h1>🦠 Malware Analysis Platform — API</h1>
    <p>Backend phân tích mã độc tĩnh đang hoạt động.</p>
    <h3>Endpoints:</h3>
    <ul>
      <li><code>POST /api/analyze</code> — tải file lên để phân tích (multipart form, field <code>file</code>)</li>
      <li><code>GET /api/health</code> — kiểm tra trạng thái</li>
      <li><code>GET /docs</code> — tài liệu API (Swagger UI)</li>
    </ul>
    </body></html>
    """


@app.get("/api/health")
def health():
    return {
        "status": "ok",
        "yara_available": yara_available(),
        "pefile_available": True,
        "version": "3.0.0",
    }


def _analyze_bytes(data: bytes, filename: str) -> dict:
    """Gói gọn phân tích từ bytes thành kết quả JSON chuẩn."""
    result = analyze_malware_bytes(data, filename)

    # Bổ sung các trường frontend cần
    return {
        "fileName": filename,
        "fileSize": result["file_size"],
        "type": result["type"],
        "family": result["family"],
        "hashes": result["hashes"],
        "fuzzyHash": result["fuzzy_hash"],
        "entropy": result["entropy"],
        "entropyVerdict": result["entropy_verdict"],
        "iocs": result["iocs"],
        "peInfo": result["pe_info"],
        "yaraMatches": result["yara_matches"],
        "threatVerdict": result["threat_verdict"],
    }


@app.post("/api/analyze")
async def analyze_file(file: UploadFile = File(...)):
    """Nhận 1 file, phân tích và trả kết quả chi tiết."""
    if not file:
        raise HTTPException(status_code=400, detail="Thiếu file")

    data = await file.read()

    if len(data) == 0:
        raise HTTPException(status_code=400, detail="File rỗng")

    if len(data) > MAX_FILE_SIZE:
        raise HTTPException(status_code=413, detail=f"File vượt quá {MAX_FILE_SIZE // (1024*1024)}MB")

    result = _analyze_bytes(data, file.filename or "unknown")
    return {"success": True, "result": result}


@app.post("/api/analyze-multiple")
async def analyze_multiple(files: List[UploadFile] = File(...)):
    """Nhận nhiều file, phân tích từng file và trả danh sách kết quả."""
    results = []
    for f in files:
        data = await f.read()
        if not data:
            continue
        results.append(_analyze_bytes(data, f.filename or "unknown"))
    return {"success": True, "count": len(results), "results": results}


if __name__ == "__main__":
    import uvicorn
    port = int(os.environ.get("PORT", "8000"))
    print(f"[*] Malware Analysis API đang chạy tại http://0.0.0.0:{port}")
    print("[*] Tài liệu API: http://localhost:" + str(port) + "/docs")
    uvicorn.run(app, host="0.0.0.0", port=port)
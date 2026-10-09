"""Weather workspace: fixed public providers, bounded caching, and per-user cities."""
from __future__ import annotations
import json
import re
import threading
import time
import urllib.error
import urllib.request
import urllib.parse
from collections import OrderedDict
from pathlib import Path
from fastapi import Depends, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel, Field, field_validator

DEFAULT_CITIES = [
    dict(id="33602", name="Tampa", state="Florida", abbr="FL", lat=27.9506, lon=-82.4572, station="KTPA", label="Tampa office"),
    dict(id="14202", name="Buffalo", state="New York", abbr="NY", lat=42.8864, lon=-78.8784, station="KBUF", label="Buffalo office"),
]
_cache = OrderedDict()
_lock = threading.Lock()


def ensure_schema(c):
    c.execute("""CREATE TABLE IF NOT EXISTS weather_user_cities (
        user_id INTEGER PRIMARY KEY REFERENCES users(id) ON DELETE CASCADE,
        cities_json TEXT NOT NULL, updated_at TEXT NOT NULL)""")


class City(BaseModel):
    id: str = Field(pattern=r"^\d{5}$")
    name: str = Field(min_length=1, max_length=100)
    state: str = Field(min_length=1, max_length=100)
    abbr: str = Field(pattern=r"^[A-Z]{2}$")
    lat: float = Field(ge=-90, le=90, allow_inf_nan=False)
    lon: float = Field(ge=-180, le=180, allow_inf_nan=False)
    station: str = Field(default="", pattern=r"^[A-Z0-9]{0,8}$")
    label: str = Field(default="", max_length=60)


class CitiesInput(BaseModel):
    cities: list[City] = Field(max_length=25)

    @field_validator("cities")
    @classmethod
    def unique(cls, value):
        if len({c.id for c in value}) != len(value):
            raise ValueError("ZIP codes must be unique")
        return value


def provider_json(url, ttl=45):
    """No arbitrary URL input; errors never become fabricated or stale success."""
    with _lock:
        cached = _cache.get(url)
        if cached and time.monotonic() - cached[0] < ttl:
            _cache.move_to_end(url)
            return cached[1]
    request = urllib.request.Request(url, headers={
        "User-Agent": "GODSEYE-Weather/4.31 (info@msapgroupllc.com)",
        "Accept": "application/geo+json, application/json"})
    try:
        with urllib.request.urlopen(request, timeout=12) as response:
            raw = response.read(2_000_001)
        if len(raw) > 2_000_000:
            raise ValueError("Weather response too large")
        value = json.loads(raw)
    except urllib.error.HTTPError as exc:
        raise HTTPException(404 if exc.code == 404 else 502, "Weather source unavailable") from exc
    except (OSError, ValueError) as exc:
        raise HTTPException(502, "Weather source unavailable; please retry") from exc
    with _lock:
        _cache[url] = (time.monotonic(), value)
        _cache.move_to_end(url)
        while len(_cache) > 256:
            _cache.popitem(last=False)
    return value


def provider_image(url, ttl):
    with _lock:
        cached = _cache.get(url)
        if cached and time.monotonic() - cached[0] < ttl:
            _cache.move_to_end(url)
            return cached[1]
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "GODSEYE-Weather/4.31 (info@msapgroupllc.com)"})
        with urllib.request.urlopen(req, timeout=10) as r:
            image = r.read(2_000_001)
        if len(image) > 2_000_000 or not (image.startswith(b"\x89PNG") or image.startswith(b"\xff\xd8")):
            raise ValueError("Invalid weather map image")
    except (OSError, ValueError) as exc:
        raise HTTPException(502, "Map tile source unavailable") from exc
    with _lock:
        _cache[url] = (time.monotonic(), image)
        while len(_cache) > 256:
            _cache.popitem(last=False)
    return image


def register_routes(app, core):
    db, current = core["db"], core["get_current_user"]
    assets = Path(core["BASE_DIR"]) / "app" / "assets" / "weather"

    @app.get("/assets/weather/{asset:path}", include_in_schema=False)
    def asset_file(asset: str, user=Depends(current)):
        allowed = {"index.html": "text/html", "app.js": "application/javascript",
                   "style.css": "text/css", "states.json": "application/json",
                   "vendor/leaflet.js": "application/javascript", "vendor/leaflet.css": "text/css"}
        if asset not in allowed:
            raise HTTPException(404, "Weather asset not found")
        return FileResponse(assets / asset, media_type=allowed[asset], headers={"Cache-Control": "no-cache"})

    @app.get("/api/v1/weather/tiles/{source}/{z}/{y}/{x}")
    async def map_tile(source: str, z: int, y: int, x: int, user=Depends(current)):
        from fastapi.responses import Response
        if source not in {"imagery", "labels", "street", "radar"} or not (0 <= z <= 18 and 0 <= x < 2**z and 0 <= y < 2**z):
            raise HTTPException(422, "Invalid map tile")
        ttl = 43200
        if source in {"imagery", "labels"}:
            service = "World_Imagery" if source == "imagery" else "Reference/World_Boundaries_and_Places"
            url = f"https://services.arcgisonline.com/ArcGIS/rest/services/{service}/MapServer/tile/{z}/{y}/{x}"
        elif source == "street":
            url = f"https://tile.openstreetmap.org/{z}/{x}/{y}.png"
            ttl = 604800
        else:
            if z > 12:
                raise HTTPException(422, "Radar supports zoom levels up to 12")
            extent = 20037508.342789244
            step = 2 * extent / (2**z)
            bbox = f"{-extent+x*step},{extent-(y+1)*step},{-extent+(x+1)*step},{extent-y*step}"
            url = "https://opengeo.ncep.noaa.gov/geoserver/conus/conus_bref_qcd/ows?" + urllib.parse.urlencode({
                "service":"WMS", "request":"GetMap", "version":"1.1.1", "layers":"conus_bref_qcd",
                "styles":"", "format":"image/png", "transparent":"true", "srs":"EPSG:3857",
                "bbox":bbox, "width":256, "height":256})
            ttl = 60
        import asyncio
        image = await asyncio.to_thread(provider_image, url, ttl)
        return Response(image, media_type="image/png" if image.startswith(b"\x89PNG") else "image/jpeg",
                        headers={"Cache-Control": f"private, max-age={ttl}"})

    @app.get("/api/v1/weather/cities")
    def cities(user=Depends(current)):
        with db() as c:
            row = c.execute("SELECT cities_json FROM weather_user_cities WHERE user_id=?", (user["id"],)).fetchone()
            permission = core["acl"].access(c, user["role"], "weather")
        return {"cities": json.loads(row[0]) if row else DEFAULT_CITIES, "can_manage": permission == "full"}

    @app.put("/api/v1/weather/cities")
    def save_cities(payload: CitiesInput, user=Depends(current)):
        encoded = json.dumps([city.model_dump() for city in payload.cities])
        with db() as c:
            c.execute("INSERT INTO weather_user_cities(user_id,cities_json,updated_at) VALUES(?,?,?) "
                      "ON CONFLICT(user_id) DO UPDATE SET cities_json=excluded.cities_json,updated_at=excluded.updated_at",
                      (user["id"], encoded, core["now"]()))
        return {"ok": True}

    @app.get("/api/v1/weather/zip/{zip_code}")
    def zip_lookup(zip_code: str, user=Depends(current)):
        if not re.fullmatch(r"\d{5}", zip_code):
            raise HTTPException(422, "Enter a five-digit U.S. ZIP code")
        return provider_json("https://api.zippopotam.us/us/" + zip_code, 86400)

    @app.get("/api/v1/weather/stations/{station}/observations/latest")
    def observation(station: str, user=Depends(current)):
        if not re.fullmatch(r"[A-Z0-9]{3,8}", station):
            raise HTTPException(422, "Invalid station")
        return provider_json("https://api.weather.gov/stations/" + station + "/observations/latest")

    @app.get("/api/v1/weather/points")
    def point(lat: float, lon: float, user=Depends(current)):
        validate_point(lat, lon)
        p = provider_json(f"https://api.weather.gov/points/{lat:.4f},{lon:.4f}", 86400)
        # Consume only a validated NOAA endpoint; never an arbitrary response URL.
        path = p.get("properties", {}).get("observationStations", "")
        if not re.fullmatch(r"https://api\.weather\.gov/gridpoints/[A-Z]{3}/\d+,\d+/stations", path):
            raise HTTPException(502, "No observation stations available")
        return provider_json(path, 86400)

    @app.get("/api/v1/weather/alerts")
    def alerts(lat: float, lon: float, user=Depends(current)):
        validate_point(lat, lon)
        return provider_json(f"https://api.weather.gov/alerts/active?point={lat:.4f},{lon:.4f}", 45)


def validate_point(lat, lon):
    if not (-90 <= lat <= 90 and -180 <= lon <= 180):
        raise HTTPException(422, "Invalid geographic coordinates")

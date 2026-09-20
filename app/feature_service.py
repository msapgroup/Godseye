"""Safe feature-status facade used by the UI and API."""
from __future__ import annotations
from .feature_registry import all_features

def feature_status():
    return {"application":"GODSEYE","features":all_features()}

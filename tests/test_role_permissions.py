import pytest
from fastapi import HTTPException
from app.main import require_permission, ROLE_PERMISSIONS


def check(role, permission):
    dep=require_permission(permission)
    return dep({'role':role,'username':role})


def test_admin_has_all_permissions():
    assert check('admin','operate')['role']=='admin'
    assert check('admin','audit.read')['role']=='admin'


def test_operator_operates_but_cannot_audit():
    assert check('operator','operate')['role']=='operator'
    assert check('operator','findings.resolve')['role']=='operator'
    with pytest.raises(HTTPException) as e: check('operator','audit.read')
    assert e.value.status_code==403


def test_auditor_reads_audit_but_cannot_operate():
    assert check('auditor','audit.read')['role']=='auditor'
    with pytest.raises(HTTPException) as e: check('auditor','operate')
    assert e.value.status_code==403


def test_readonly_cannot_operate_or_audit():
    for permission in ('operate','audit.read','findings.resolve','notifications.retry'):
        with pytest.raises(HTTPException) as e: check('readonly',permission)
        assert e.value.status_code==403

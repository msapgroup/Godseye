"""Local customer records for the GODSEYE CRM workspace."""
from __future__ import annotations

import sqlite3
from typing import Literal

from fastapi import Depends, HTTPException, Request
from pydantic import BaseModel, Field, field_validator


class CustomerInput(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    customer_type: Literal["business", "individual"] = "business"
    status: Literal["active", "prospect", "inactive"] = "active"
    email: str = Field(default="", max_length=254)
    phone: str = Field(default="", max_length=80)
    address: str = Field(default="", max_length=400)
    notes: str = Field(default="", max_length=5000)
    site_id: int | None = None

    @field_validator("name", "email", "phone", "address", "notes")
    @classmethod
    def trim(cls, value: str) -> str:
        return value.strip()

    @field_validator("email")
    @classmethod
    def email_format(cls, value: str) -> str:
        if value and ("@" not in value or value.startswith("@") or value.endswith("@")):
            raise ValueError("Enter a valid email address")
        return value

    @field_validator("name")
    @classmethod
    def nonempty_name(cls, value: str) -> str:
        if not value:
            raise ValueError("Customer name is required")
        return value


class ContactInput(BaseModel):
    name: str = Field(min_length=1, max_length=160)
    role: str = Field(default="", max_length=120)
    email: str = Field(default="", max_length=254)
    phone: str = Field(default="", max_length=80)

    @field_validator("name", "role", "email", "phone")
    @classmethod
    def trim(cls, value: str) -> str:
        return value.strip()

    @field_validator("email")
    @classmethod
    def email_format(cls, value: str) -> str:
        if value and ("@" not in value or value.startswith("@") or value.endswith("@")):
            raise ValueError("Enter a valid email address")
        return value

    @field_validator("name")
    @classmethod
    def nonempty_name(cls, value: str) -> str:
        if not value:
            raise ValueError("Contact name is required")
        return value


def ensure_schema(c: sqlite3.Connection) -> None:
    c.executescript("""
    CREATE TABLE IF NOT EXISTS crm_customers (
        id INTEGER PRIMARY KEY,
        name TEXT NOT NULL,
        customer_type TEXT NOT NULL DEFAULT 'business',
        status TEXT NOT NULL DEFAULT 'active',
        email TEXT NOT NULL DEFAULT '',
        phone TEXT NOT NULL DEFAULT '',
        address TEXT NOT NULL DEFAULT '',
        notes TEXT NOT NULL DEFAULT '',
        site_id INTEGER,
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS crm_contacts (
        id INTEGER PRIMARY KEY,
        customer_id INTEGER NOT NULL REFERENCES crm_customers(id) ON DELETE CASCADE,
        name TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT '',
        email TEXT NOT NULL DEFAULT '',
        phone TEXT NOT NULL DEFAULT '',
        created_at TEXT NOT NULL,
        updated_at TEXT NOT NULL
    );
    """)
    # Existing installations may already have customer/contact tables from an
    # earlier build. CREATE TABLE IF NOT EXISTS leaves such schemas untouched;
    # migrate any missing fields before a save attempts to use them.
    customer_columns = {row["name"] for row in c.execute("PRAGMA table_info(crm_customers)")}
    contact_columns = {row["name"] for row in c.execute("PRAGMA table_info(crm_contacts)")}
    for name, definition in {
        "customer_type": "TEXT NOT NULL DEFAULT 'business'",
        "status": "TEXT NOT NULL DEFAULT 'active'",
        "email": "TEXT NOT NULL DEFAULT ''",
        "phone": "TEXT NOT NULL DEFAULT ''",
        "address": "TEXT NOT NULL DEFAULT ''",
        "notes": "TEXT NOT NULL DEFAULT ''",
        "site_id": "INTEGER",
        "created_at": "TEXT NOT NULL DEFAULT ''",
        "updated_at": "TEXT NOT NULL DEFAULT ''",
    }.items():
        if name not in customer_columns:
            c.execute(f"ALTER TABLE crm_customers ADD COLUMN {name} {definition}")
    for name, definition in {
        "customer_id": "INTEGER NOT NULL DEFAULT 0",
        "role": "TEXT NOT NULL DEFAULT ''",
        "email": "TEXT NOT NULL DEFAULT ''",
        "phone": "TEXT NOT NULL DEFAULT ''",
        "created_at": "TEXT NOT NULL DEFAULT ''",
        "updated_at": "TEXT NOT NULL DEFAULT ''",
    }.items():
        if name not in contact_columns:
            c.execute(f"ALTER TABLE crm_contacts ADD COLUMN {name} {definition}")
    c.execute("CREATE INDEX IF NOT EXISTS crm_customer_name_idx ON crm_customers(name COLLATE NOCASE)")
    c.execute("CREATE INDEX IF NOT EXISTS crm_contact_customer_idx ON crm_contacts(customer_id)")


def register_routes(app, core) -> None:
    def ensure_site(c, site_id):
        if site_id is not None and not c.execute("SELECT 1 FROM managed_sites WHERE id=?", (site_id,)).fetchone():
            raise HTTPException(400, "Select an existing linked site")

    def get_customer(c, customer_id):
        row = c.execute("""SELECT c.*, s.name AS site_name, s.status AS site_status,
            (SELECT COUNT(*) FROM crm_contacts WHERE customer_id=c.id) AS contact_count
            FROM crm_customers c LEFT JOIN managed_sites s ON s.id=c.site_id
            WHERE c.id=?""", (customer_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Customer not found")
        result = dict(row)
        result["contacts"] = [dict(x) for x in c.execute(
            "SELECT * FROM crm_contacts WHERE customer_id=? ORDER BY name COLLATE NOCASE, id", (customer_id,))]
        return result

    @app.get("/api/v1/crm/customers")
    def list_customers(q: str = "", user=Depends(core.get_current_user)):
        with core.db() as c:
            return [dict(row) for row in c.execute("""SELECT c.*, s.name AS site_name,
                (SELECT COUNT(*) FROM crm_contacts WHERE customer_id=c.id) AS contact_count
                FROM crm_customers c LEFT JOIN managed_sites s ON s.id=c.site_id
                WHERE ?='' OR c.name LIKE ? ESCAPE '\\' OR c.email LIKE ? ESCAPE '\\'
                ORDER BY c.name COLLATE NOCASE, c.id LIMIT 500""",
                (q.strip(), *("%" + q.strip().replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_") + "%",)*2))]

    @app.get("/api/v1/crm/customers/{customer_id}")
    def customer_detail(customer_id: int, user=Depends(core.get_current_user)):
        with core.db() as c:
            return get_customer(c, customer_id)

    @app.post("/api/v1/crm/customers", status_code=201)
    def create_customer(payload: CustomerInput, request: Request, user=Depends(core.require_permission("operate"))):
        with core.db() as c:
            ensure_site(c, payload.site_id)
            data = payload.model_dump()
            ts = core.now()
            cursor = c.execute("""INSERT INTO crm_customers
                (name,customer_type,status,email,phone,address,notes,site_id,created_at,updated_at)
                VALUES (:name,:customer_type,:status,:email,:phone,:address,:notes,:site_id,:created_at,:updated_at)""",
                {**data, "created_at": ts, "updated_at": ts})
            core.audit(c, user["username"], "crm_customer_created", str(cursor.lastrowid), data["name"], core.client_ip(request))
            return get_customer(c, cursor.lastrowid)

    @app.put("/api/v1/crm/customers/{customer_id}")
    def update_customer(customer_id: int, payload: CustomerInput, request: Request,
                        user=Depends(core.require_permission("operate"))):
        with core.db() as c:
            get_customer(c, customer_id)
            ensure_site(c, payload.site_id)
            c.execute("""UPDATE crm_customers SET name=:name,customer_type=:customer_type,status=:status,
                email=:email,phone=:phone,address=:address,notes=:notes,site_id=:site_id,updated_at=:updated_at
                WHERE id=:id""", {**payload.model_dump(), "updated_at": core.now(), "id": customer_id})
            core.audit(c, user["username"], "crm_customer_updated", str(customer_id), payload.name, core.client_ip(request))
            return get_customer(c, customer_id)

    @app.delete("/api/v1/crm/customers/{customer_id}")
    def delete_customer(customer_id: int, request: Request, user=Depends(core.require_admin)):
        with core.db() as c:
            row = get_customer(c, customer_id)
            c.execute("DELETE FROM crm_contacts WHERE customer_id=?", (customer_id,))
            c.execute("DELETE FROM crm_customers WHERE id=?", (customer_id,))
            core.audit(c, user["username"], "crm_customer_deleted", str(customer_id), row["name"], core.client_ip(request))
            return {"ok": True}

    @app.post("/api/v1/crm/customers/{customer_id}/contacts", status_code=201)
    def add_contact(customer_id: int, payload: ContactInput, request: Request,
                    user=Depends(core.require_permission("operate"))):
        with core.db() as c:
            get_customer(c, customer_id)
            ts = core.now()
            cursor = c.execute("""INSERT INTO crm_contacts
                (customer_id,name,role,email,phone,created_at,updated_at) VALUES (?,?,?,?,?,?,?)""",
                (customer_id, payload.name, payload.role, payload.email, payload.phone, ts, ts))
            core.audit(c, user["username"], "crm_contact_created", str(cursor.lastrowid), str(customer_id), core.client_ip(request))
            return dict(c.execute("SELECT * FROM crm_contacts WHERE id=?", (cursor.lastrowid,)).fetchone())

    @app.put("/api/v1/crm/customers/{customer_id}/contacts/{contact_id}")
    def update_contact(customer_id: int, contact_id: int, payload: ContactInput, request: Request,
                       user=Depends(core.require_permission("operate"))):
        with core.db() as c:
            if not c.execute("SELECT 1 FROM crm_contacts WHERE id=? AND customer_id=?", (contact_id, customer_id)).fetchone():
                raise HTTPException(404, "Contact not found")
            c.execute("""UPDATE crm_contacts SET name=?,role=?,email=?,phone=?,updated_at=?
                WHERE id=? AND customer_id=?""", (payload.name, payload.role, payload.email, payload.phone,
                                                      core.now(), contact_id, customer_id))
            core.audit(c, user["username"], "crm_contact_updated", str(contact_id), str(customer_id), core.client_ip(request))
            return dict(c.execute("SELECT * FROM crm_contacts WHERE id=?", (contact_id,)).fetchone())

    @app.delete("/api/v1/crm/customers/{customer_id}/contacts/{contact_id}")
    def delete_contact(customer_id: int, contact_id: int, request: Request,
                       user=Depends(core.require_permission("operate"))):
        with core.db() as c:
            if not c.execute("SELECT 1 FROM crm_contacts WHERE id=? AND customer_id=?", (contact_id, customer_id)).fetchone():
                raise HTTPException(404, "Contact not found")
            c.execute("DELETE FROM crm_contacts WHERE id=? AND customer_id=?", (contact_id, customer_id))
            core.audit(c, user["username"], "crm_contact_deleted", str(contact_id), str(customer_id), core.client_ip(request))
            return {"ok": True}

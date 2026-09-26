"""Local customer records for the GODSEYE CRM workspace."""
from __future__ import annotations

import sqlite3
import json
import re
from urllib.parse import unquote, quote
from typing import Literal

from fastapi import Depends, HTTPException, Request
from fastapi.responses import Response
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
    new_kb = not c.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='kb_articles'").fetchone()
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
    c.executescript("""
    CREATE TABLE IF NOT EXISTS kb_articles (
        id INTEGER PRIMARY KEY, title TEXT NOT NULL, product TEXT NOT NULL DEFAULT '',
        category TEXT NOT NULL DEFAULT '', visibility TEXT NOT NULL DEFAULT 'team',
        customer_id INTEGER, site_id INTEGER, summary TEXT NOT NULL DEFAULT '',
        prerequisites TEXT NOT NULL DEFAULT '', expected_result TEXT NOT NULL DEFAULT '',
        troubleshooting TEXT NOT NULL DEFAULT '', tags TEXT NOT NULL DEFAULT '',
        source_url TEXT NOT NULL DEFAULT '', steps_json TEXT NOT NULL DEFAULT '[]',
        created_by TEXT NOT NULL, created_at TEXT NOT NULL, updated_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS workspace_files (
        id INTEGER PRIMARY KEY, owner_type TEXT NOT NULL CHECK(owner_type IN ('customer','article')),
        owner_id INTEGER NOT NULL, filename TEXT NOT NULL, media_type TEXT NOT NULL,
        size INTEGER NOT NULL, contents BLOB NOT NULL, uploaded_by TEXT NOT NULL,
        created_at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS workspace_files_owner_idx ON workspace_files(owner_type,owner_id);
    """)
    if new_kb:
        steps = [
            {"title":"Open account settings", "instructions":"In new Outlook, select View settings, then Accounts > Your accounts.", "image":"/assets/kb-outlook-settings.svg", "link":""},
            {"title":"Add the account", "instructions":"Under Email accounts, select Add Account. Enter the work email address and select Continue.", "image":"/assets/kb-outlook-account.svg", "link":""},
            {"title":"Sign in and verify", "instructions":"Complete Microsoft sign-in and multifactor authentication. Open Inbox and send and receive a test message.", "image":"/assets/kb-outlook-verify.svg", "link":""},
        ]
        c.execute("""INSERT INTO kb_articles(id,title,product,category,summary,prerequisites,expected_result,
            troubleshooting,tags,source_url,steps_json,created_by,created_at,updated_at)
            VALUES (1,?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
            "Set up Outlook on a Windows computer", "Microsoft 365", "Email",
            "Add a Microsoft 365 work mailbox to new Outlook for Windows.",
            "Confirm the user has an active mailbox, an Outlook installation, and access to sign-in and MFA.",
            "The mailbox appears in Outlook and a test email can be sent and received.",
            "If the menus differ, check whether classic Outlook is installed. For classic Outlook, use File > Add Account. Check the user's license and MFA if sign-in fails.",
            "Outlook,Windows,Microsoft 365", "https://support.microsoft.com/en-us/outlook/getstarted/add-an-email-account-to-outlook-for-windows",
            json.dumps(steps), "GODSEYE", "2026-09-26T00:00:00Z", "2026-09-26T00:00:00Z"))


class ArticleStep(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    instructions: str = Field(default="", max_length=5000)
    image: str = Field(default="", max_length=500)
    link: str = Field(default="", max_length=1000)


class ArticleInput(BaseModel):
    title: str = Field(min_length=1, max_length=160)
    product: str = Field(default="", max_length=120)
    category: str = Field(default="", max_length=120)
    visibility: Literal["team", "customer"] = "team"
    customer_id: int | None = None
    site_id: int | None = None
    summary: str = Field(default="", max_length=5000)
    prerequisites: str = Field(default="", max_length=5000)
    expected_result: str = Field(default="", max_length=5000)
    troubleshooting: str = Field(default="", max_length=5000)
    tags: str = Field(default="", max_length=500)
    source_url: str = Field(default="", max_length=1000)
    steps: list[ArticleStep] = Field(default_factory=list, max_length=60)


def safe_url(value: str) -> bool:
    return not value or (value.startswith("https://") and len(value) > 8)


def register_routes(app, core) -> None:
    def article(c, article_id):
        row = c.execute("SELECT * FROM kb_articles WHERE id=?", (article_id,)).fetchone()
        if not row:
            raise HTTPException(404, "Article not found")
        data = dict(row)
        data["steps"] = json.loads(data.pop("steps_json"))
        data["files"] = files_for(c, "article", article_id)
        return data

    def files_for(c, owner_type, owner_id):
        return [dict(row) for row in c.execute("""SELECT id,filename,media_type,size,uploaded_by,created_at
            FROM workspace_files WHERE owner_type=? AND owner_id=? ORDER BY id DESC""", (owner_type, owner_id))]

    def check_article_links(payload):
        if not safe_url(payload.source_url) or any(not safe_url(s.link) or
                (s.image and not (s.image.startswith('/assets/kb-outlook-') or s.image.startswith('/api/v1/workspace-files/')))
                for s in payload.steps):
            raise HTTPException(400, "Use HTTPS links and uploaded article images")

    @app.get("/api/v1/kb/articles")
    def list_articles(q: str = "", user=Depends(core.get_current_user)):
        with core.db() as c:
            return [dict(x) for x in c.execute("""SELECT id,title,product,category,summary,tags,updated_at
                FROM kb_articles WHERE ?='' OR title LIKE ? OR product LIKE ? OR category LIKE ? OR tags LIKE ?
                OR summary LIKE ? OR prerequisites LIKE ? OR troubleshooting LIKE ? OR steps_json LIKE ?
                ORDER BY updated_at DESC,id DESC LIMIT 500""", (q.strip(), *(("%"+q.strip().replace("%", "\\%").replace("_", "\\_")+"%",)*8)))]

    @app.get("/api/v1/kb/articles/{article_id}")
    def get_article(article_id: int, user=Depends(core.get_current_user)):
        with core.db() as c: return article(c, article_id)

    @app.post("/api/v1/kb/articles", status_code=201)
    def create_article(payload: ArticleInput, request: Request, user=Depends(core.require_permission("operate"))):
        check_article_links(payload)
        with core.db() as c:
            data=payload.model_dump(); steps=data.pop("steps");data["steps_json"]=json.dumps(steps)
            ts=core.now();data.update(created_by=user["username"],created_at=ts,updated_at=ts)
            keys=','.join(data); placeholders=','.join(':'+k for k in data)
            cur=c.execute(f"INSERT INTO kb_articles ({keys}) VALUES ({placeholders})",data)
            core.audit(c,user["username"],"kb_article_created",str(cur.lastrowid),payload.title,core.client_ip(request))
            return article(c,cur.lastrowid)

    @app.put("/api/v1/kb/articles/{article_id}")
    def update_article(article_id: int,payload: ArticleInput,request: Request,user=Depends(core.require_permission("operate"))):
        check_article_links(payload)
        with core.db() as c:
            article(c,article_id);data=payload.model_dump();data["steps_json"]=json.dumps(data.pop("steps"));data["updated_at"]=core.now();data["id"]=article_id
            c.execute("UPDATE kb_articles SET "+','.join(k+'=:'+k for k in data if k!='id')+" WHERE id=:id",data)
            core.audit(c,user["username"],"kb_article_updated",str(article_id),payload.title,core.client_ip(request))
            return article(c,article_id)

    @app.delete("/api/v1/kb/articles/{article_id}")
    def delete_article(article_id: int,request: Request,user=Depends(core.require_admin)):
        with core.db() as c:
            old=article(c,article_id)
            c.execute("DELETE FROM workspace_files WHERE owner_type='article' AND owner_id=?",(article_id,))
            c.execute("DELETE FROM kb_articles WHERE id=?",(article_id,))
            core.audit(c,user["username"],"kb_article_deleted",str(article_id),old["title"],core.client_ip(request))
            return {"ok":True}

    @app.post("/api/v1/workspace-files/{owner_type}/{owner_id}", status_code=201)
    async def upload_file(owner_type: Literal["customer","article"],owner_id: int,request: Request,
                          user=Depends(core.require_permission("operate"))):
        filename=unquote(request.headers.get("x-filename", ""))
        filename=filename.replace("\\", "/").split("/")[-1].strip()
        if not filename or len(filename)>180 or not re.fullmatch(r"[\w .()\-]+",filename,re.UNICODE):
            raise HTTPException(400,"Invalid filename")
        media=request.headers.get("content-type", "application/octet-stream").split(';')[0].lower()
        allowed={"image/png","image/jpeg","image/webp","image/gif","application/pdf","text/plain",
                 "text/csv","application/msword","application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                 "application/vnd.ms-excel","application/vnd.openxmlformats-officedocument.spreadsheetml.sheet"}
        if media not in allowed: raise HTTPException(415,"Unsupported file type")
        data=bytearray()
        async for part in request.stream():
            data.extend(part)
            if len(data)>10*1024*1024: raise HTTPException(413,"File exceeds the 10 MB limit")
        if not data: raise HTTPException(400,"File is empty")
        with core.db() as c:
            table="crm_customers" if owner_type=="customer" else "kb_articles"
            if not c.execute(f"SELECT 1 FROM {table} WHERE id=?",(owner_id,)).fetchone():
                raise HTTPException(404,"Record not found")
            cur=c.execute("""INSERT INTO workspace_files(owner_type,owner_id,filename,media_type,size,contents,uploaded_by,created_at)
                VALUES(?,?,?,?,?,?,?,?)""",(owner_type,owner_id,filename,media,len(data),bytes(data),user["username"],core.now()))
            core.audit(c,user["username"],"workspace_file_uploaded",str(cur.lastrowid),f"{owner_type}:{owner_id}",core.client_ip(request))
            return {"id":cur.lastrowid,"filename":filename,"size":len(data)}

    @app.get("/api/v1/workspace-files/{file_id}")
    def download_file(file_id: int,user=Depends(core.get_current_user)):
        with core.db() as c:
            row=c.execute("SELECT * FROM workspace_files WHERE id=?",(file_id,)).fetchone()
            if not row: raise HTTPException(404,"File not found")
            return Response(bytes(row["contents"]),media_type=row["media_type"],headers={
                "Content-Disposition": "attachment; filename*=UTF-8''"+quote(row["filename"]),
                "X-Content-Type-Options":"nosniff", "Cache-Control":"private, no-store"})

    @app.delete("/api/v1/workspace-files/{file_id}")
    def remove_file(file_id: int,request: Request,user=Depends(core.require_permission("operate"))):
        with core.db() as c:
            row=c.execute("SELECT owner_type,owner_id FROM workspace_files WHERE id=?",(file_id,)).fetchone()
            if not row: raise HTTPException(404,"File not found")
            c.execute("DELETE FROM workspace_files WHERE id=?",(file_id,))
            core.audit(c,user["username"],"workspace_file_deleted",str(file_id),f'{row["owner_type"]}:{row["owner_id"]}',core.client_ip(request))
            return {"ok":True}
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
        result["files"] = files_for(c,"customer",customer_id)
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
            c.execute("DELETE FROM workspace_files WHERE owner_type='customer' AND owner_id=?", (customer_id,))
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

"""Application Database Engine and Seed Models."""

import os
from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Integer,
    String,
    Text,
    create_engine,
    text,
)
from sqlalchemy.pool import StaticPool
from sqlalchemy.orm import declarative_base, sessionmaker
from datetime import datetime, timezone

Base = declarative_base()


class Employee(Base):
    __tablename__ = "employees"

    id = Column(Integer, primary_key=True, index=True)
    emp_id = Column(String(32), unique=True, index=True)
    full_name = Column(String(128), nullable=False)
    email = Column(String(128), nullable=False)
    department = Column(String(64), nullable=False)
    role = Column(String(64), nullable=False)
    salary = Column(Integer, nullable=False)
    ssn = Column(String(32), nullable=False)


class ConfidentialDocument(Base):
    __tablename__ = "confidential_documents"

    id = Column(Integer, primary_key=True, index=True)
    doc_id = Column(String(32), unique=True, index=True)
    owner_id = Column(Integer, nullable=False)
    title = Column(String(256), nullable=False)
    classification = Column(String(32), default="RESTRICTED")
    content = Column(Text, nullable=False)


class PortalUser(Base):
    __tablename__ = "portal_users"

    id = Column(Integer, primary_key=True, index=True)
    username = Column(String(64), unique=True, index=True)
    password_hash = Column(String(128), nullable=False)
    is_admin = Column(Boolean, default=False)
    role = Column(String(32), default="User")


def init_db(database_url: str = "sqlite:///:memory:"):
    """Initialize database tables and populate baseline mock data."""
    if database_url.startswith("sqlite:///./data/"):
        os.makedirs("./data", exist_ok=True)

    connect_args = {}
    engine_kwargs = {}
    if database_url.startswith("sqlite"):
        connect_args["check_same_thread"] = False
        if ":memory:" in database_url:
            engine_kwargs["poolclass"] = StaticPool

    engine = create_engine(
        database_url, connect_args=connect_args, **engine_kwargs
    )
    Base.metadata.create_all(bind=engine)
    SessionLocal = sessionmaker(
        autocommit=False, autoflush=False, bind=engine
    )

    db = SessionLocal()
    try:
        # Check if already seeded
        if db.query(Employee).count() == 0:
            seed_employees = [
                Employee(
                    emp_id="EMP-1001",
                    full_name="John Doe",
                    email="jdoe@corp.enterprise.local",
                    department="Finance",
                    role="Senior Financial Analyst",
                    salary=115000,
                    ssn="***-**-4819",
                ),
                Employee(
                    emp_id="EMP-1002",
                    full_name="Alice Smith",
                    email="asmith@corp.enterprise.local",
                    department="Human Resources",
                    role="HR Operations Lead",
                    salary=98000,
                    ssn="***-**-3312",
                ),
                Employee(
                    emp_id="EMP-1003",
                    full_name="Bruce Wayne",
                    email="bwayne@corp.enterprise.local",
                    department="IT Operations",
                    role="Systems Administrator",
                    salary=125000,
                    ssn="***-**-9901",
                ),
                Employee(
                    emp_id="EMP-0001",
                    full_name="David Johnson",
                    email="djohnson.admin@corp.enterprise.local",
                    department="Executive",
                    role="Infrastructure Director",
                    salary=220000,
                    ssn="***-**-1100",
                ),
            ]
            db.add_all(seed_employees)

            seed_docs = [
                ConfidentialDocument(
                    doc_id="DOC-9001",
                    owner_id=1,
                    title="Q3 Strategic Financial Forecast",
                    classification="RESTRICTED",
                    content="Confidential financial acquisition roadmap and budget allocations.",
                ),
                ConfidentialDocument(
                    doc_id="DOC-9002",
                    owner_id=2,
                    title="HR Executive Compensation Plan",
                    classification="CONFIDENTIAL",
                    content="Executive salary bands, bonus structures, and performance targets.",
                ),
                ConfidentialDocument(
                    doc_id="DOC-9003",
                    owner_id=3,
                    title="Core Infrastructure Network Keys",
                    classification="SECRET",
                    content="Internal bastion keys, router admin passwords, and VPN configurations.",
                ),
            ]
            db.add_all(seed_docs)

            seed_users = [
                PortalUser(
                    username="jdoe",
                    password_hash="$2b$12$labPasswordHashJohnDoeDemoOnly",
                    is_admin=False,
                    role="Finance",
                ),
                PortalUser(
                    username="asmith",
                    password_hash="$2b$12$labPasswordHashAliceSmithDemoOnly",
                    is_admin=False,
                    role="HR",
                ),
                PortalUser(
                    username="admin",
                    password_hash="$2b$12$labPasswordHashAdministratorDemoOnly",
                    is_admin=True,
                    role="Administrator",
                ),
            ]
            db.add_all(seed_users)

            db.commit()
    finally:
        db.close()

    return engine, SessionLocal

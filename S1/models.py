from datetime import datetime
from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()

class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String, nullable=False)
    start_time = db.Column(db.DateTime, default=datetime.utcnow)
    end_time = db.Column(db.DateTime, nullable=True)
    total_sites = db.Column(db.Integer, default=0)

    details = db.relationship("ScanDetail", backref="scan", cascade="all, delete-orphan")

class ScanDetail(db.Model):
    __tablename__ = "scan_details"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id"), nullable=False)
    site_name = db.Column(db.String, nullable=False)
    site_url = db.Column(db.String, nullable=False)

class Observation(db.Model):
    __tablename__ = "observations"

    stamp = db.Column(db.DateTime, primary_key=True)
    tmsi1 = db.Column(db.String)
    tmsi2 = db.Column(db.String)
    imsi = db.Column(db.String)
    imsicountry = db.Column(db.String)
    imsibrand = db.Column(db.String)
    imsioperator = db.Column(db.String)
    mcc = db.Column(db.Integer)
    mnc = db.Column(db.Integer)
    lac = db.Column(db.Integer)
    cell = db.Column(db.Integer)

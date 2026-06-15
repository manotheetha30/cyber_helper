"""
CTI Pipeline – Storage Layer
Aligned with the new models (behaviors, attack_mappings as separate fields).
"""
from __future__ import annotations
import json
import logging
from datetime import datetime, timedelta

from sqlalchemy import (
    Column, DateTime, Float, Integer, String, Text,
    UniqueConstraint, create_engine,
)
from sqlalchemy.orm import DeclarativeBase, Session, sessionmaker

from settings import DATABASE_URL
from models import CTIReport, ExtractedArticle

logger = logging.getLogger(__name__)


class Base(DeclarativeBase):
    pass


class ArticleRecord(Base):
    __tablename__ = "articles"
    __table_args__ = (UniqueConstraint("content_hash", name="uq_content_hash"),)

    id                = Column(Integer, primary_key=True, autoincrement=True)
    url               = Column(String(2048), nullable=False, index=True)
    title             = Column(String(512))
    source            = Column(String(128))
    author            = Column(String(256))
    published_date    = Column(DateTime)
    extracted_at      = Column(DateTime, default=datetime.utcnow)
    extraction_method = Column(String(64))
    char_count        = Column(Integer)
    word_count        = Column(Integer)
    content_hash      = Column(String(64), unique=True)
    full_text         = Column(Text)


class CTIReportRecord(Base):
    __tablename__ = "cti_reports"

    id                    = Column(Integer, primary_key=True, autoincrement=True)
    article_url           = Column(String(2048), index=True)
    generated_at          = Column(DateTime, default=datetime.utcnow)
    model_used            = Column(String(128))
    processing_time_s     = Column(Float)
    executive_summary     = Column(Text)
    threat_actors_json    = Column(Text)
    campaigns_json        = Column(Text)
    malware_json          = Column(Text)
    iocs_json             = Column(Text)
    behaviors_json        = Column(Text)
    attack_mappings_json  = Column(Text)
    hunt_hypotheses_json  = Column(Text)


_engine = None


def get_engine():
    global _engine
    if _engine is None:
        import os; os.makedirs("data", exist_ok=True)
        _engine = create_engine(DATABASE_URL, echo=False)
        Base.metadata.create_all(_engine)
        logger.info("Database ready: %s", DATABASE_URL)
    return _engine


def _session() -> Session:
    return sessionmaker(bind=get_engine(), expire_on_commit=False)()


def save_article(article: ExtractedArticle) -> bool:
    with _session() as s:
        if s.query(ArticleRecord).filter_by(content_hash=article.content_hash).first():
            return False
        rss = article.rss_article
        s.add(ArticleRecord(
            url=rss.url, title=rss.title, source=rss.source,
            author=rss.author, published_date=rss.published_date,
            extracted_at=article.extracted_at,
            extraction_method=article.extraction_method,
            char_count=article.char_count, word_count=article.word_count,
            content_hash=article.content_hash, full_text=article.full_text,
        ))
        s.commit()
        return True


def save_report(report: CTIReport) -> None:
    with _session() as s:
        s.add(CTIReportRecord(
            article_url          = report.article.rss_article.url,
            generated_at         = report.generated_at,
            model_used           = report.model_used,
            processing_time_s    = report.processing_time_s,
            executive_summary    = report.executive_summary,
            threat_actors_json   = json.dumps([x.model_dump() for x in report.threat_actors]),
            campaigns_json       = json.dumps([x.model_dump() for x in report.campaigns]),
            malware_json         = json.dumps([x.model_dump() for x in report.malware]),
            iocs_json            = json.dumps([x.model_dump() for x in report.iocs]),
            behaviors_json       = json.dumps([x.model_dump() for x in report.behaviors]),
            attack_mappings_json = json.dumps([x.model_dump() for x in report.attack_mappings]),
            hunt_hypotheses_json = json.dumps([x.model_dump() for x in report.hunt_hypotheses]),
        ))
        s.commit()
    logger.debug("Saved report: %s", report.article.rss_article.url[:80])


def is_duplicate(content_hash: str) -> bool:
    with _session() as s:
        return s.query(ArticleRecord).filter_by(content_hash=content_hash).first() is not None


def get_recent_reports(days: int = 7) -> list[CTIReportRecord]:
    cutoff = datetime.utcnow() - timedelta(days=days)
    with _session() as s:
        return (s.query(CTIReportRecord)
                  .filter(CTIReportRecord.generated_at >= cutoff)
                  .order_by(CTIReportRecord.generated_at.desc())
                  .all())

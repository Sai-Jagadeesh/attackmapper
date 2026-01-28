"""SQLite caching layer for threat intelligence data."""

import json
import sqlite3
from datetime import datetime, timedelta
from pathlib import Path
from typing import Optional, Any

from attackmapper.core.models import CVEInfo, ThreatActor, InfrastructureType


class IntelCache:
    """SQLite-based cache for threat intelligence data."""

    def __init__(self, db_path: Optional[str] = None):
        if db_path is None:
            # Default to user's cache directory
            cache_dir = Path.home() / ".cache" / "attackmapper"
            cache_dir.mkdir(parents=True, exist_ok=True)
            db_path = str(cache_dir / "intel_cache.db")

        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        """Initialize the database schema."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            # CVE table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cves (
                    cve_id TEXT PRIMARY KEY,
                    description TEXT,
                    cvss_score REAL,
                    severity TEXT,
                    affected_products TEXT,
                    affected_infrastructure TEXT,
                    exploitation_status TEXT,
                    references_json TEXT,
                    published_date TEXT,
                    cached_at TEXT
                )
            """)

            # Threat actors table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS threat_actors (
                    name TEXT PRIMARY KEY,
                    aliases TEXT,
                    description TEXT,
                    targeted_infrastructure TEXT,
                    ttps TEXT,
                    recent_activity TEXT,
                    references_json TEXT,
                    cached_at TEXT
                )
            """)

            # Generic key-value cache for other data
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS cache (
                    key TEXT PRIMARY KEY,
                    value TEXT,
                    cached_at TEXT
                )
            """)

            # Metadata table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT
                )
            """)

            # Custom feeds table
            cursor.execute("""
                CREATE TABLE IF NOT EXISTS custom_feeds (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    name TEXT UNIQUE NOT NULL,
                    url TEXT NOT NULL,
                    feed_type TEXT DEFAULT 'json',
                    infrastructure TEXT,
                    enabled INTEGER DEFAULT 1,
                    last_fetched TEXT,
                    created_at TEXT
                )
            """)

            conn.commit()

    def cache_cve(self, cve: CVEInfo):
        """Cache a CVE entry."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO cves
                (cve_id, description, cvss_score, severity, affected_products,
                 affected_infrastructure, exploitation_status, references_json,
                 published_date, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                cve.cve_id,
                cve.description,
                cve.cvss_score,
                cve.severity,
                json.dumps(cve.affected_products),
                json.dumps([i.value for i in cve.affected_infrastructure]),
                cve.exploitation_status,
                json.dumps(cve.references),
                cve.published_date,
                datetime.now().isoformat(),
            ))
            conn.commit()

    def get_cves(
        self,
        infrastructure: Optional[InfrastructureType] = None,
        severity: Optional[str] = None,
        max_age_hours: int = 24,
    ) -> list[CVEInfo]:
        """Retrieve cached CVEs, optionally filtered."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM cves WHERE 1=1"
            params: list[Any] = []

            if infrastructure:
                query += " AND affected_infrastructure LIKE ?"
                params.append(f'%"{infrastructure.value}"%')

            if severity:
                query += " AND severity = ?"
                params.append(severity)

            # Check cache freshness
            cutoff = (datetime.now() - timedelta(hours=max_age_hours)).isoformat()
            query += " AND cached_at > ?"
            params.append(cutoff)

            query += " ORDER BY cvss_score DESC"

            cursor.execute(query, params)
            rows = cursor.fetchall()

            cves = []
            for row in rows:
                cves.append(CVEInfo(
                    cve_id=row[0],
                    description=row[1],
                    cvss_score=row[2],
                    severity=row[3],
                    affected_products=json.loads(row[4]) if row[4] else [],
                    affected_infrastructure=[
                        InfrastructureType(i) for i in json.loads(row[5])
                    ] if row[5] else [],
                    exploitation_status=row[6],
                    references=json.loads(row[7]) if row[7] else [],
                    published_date=row[8],
                ))
            return cves

    def cache_threat_actor(self, actor: ThreatActor):
        """Cache a threat actor entry."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO threat_actors
                (name, aliases, description, targeted_infrastructure, ttps,
                 recent_activity, references_json, cached_at)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                actor.name,
                json.dumps(actor.aliases),
                actor.description,
                json.dumps([i.value for i in actor.targeted_infrastructure]),
                json.dumps(actor.ttps),
                actor.recent_activity,
                json.dumps(actor.references),
                datetime.now().isoformat(),
            ))
            conn.commit()

    def get_threat_actors(
        self,
        infrastructure: Optional[InfrastructureType] = None,
        max_age_hours: int = 168,  # 1 week default
    ) -> list[ThreatActor]:
        """Retrieve cached threat actors, optionally filtered by target infrastructure."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            query = "SELECT * FROM threat_actors WHERE 1=1"
            params: list[Any] = []

            if infrastructure:
                query += " AND targeted_infrastructure LIKE ?"
                params.append(f'%"{infrastructure.value}"%')

            cutoff = (datetime.now() - timedelta(hours=max_age_hours)).isoformat()
            query += " AND cached_at > ?"
            params.append(cutoff)

            cursor.execute(query, params)
            rows = cursor.fetchall()

            actors = []
            for row in rows:
                actors.append(ThreatActor(
                    name=row[0],
                    aliases=json.loads(row[1]) if row[1] else [],
                    description=row[2],
                    targeted_infrastructure=[
                        InfrastructureType(i) for i in json.loads(row[3])
                    ] if row[3] else [],
                    ttps=json.loads(row[4]) if row[4] else [],
                    recent_activity=row[5],
                    references=json.loads(row[6]) if row[6] else [],
                ))
            return actors

    def set_cache(self, key: str, value: Any):
        """Store a value in the generic cache."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO cache (key, value, cached_at)
                VALUES (?, ?, ?)
            """, (key, json.dumps(value), datetime.now().isoformat()))
            conn.commit()

    def get_cache(self, key: str, max_age_hours: int = 24) -> Optional[Any]:
        """Retrieve a value from the generic cache."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cutoff = (datetime.now() - timedelta(hours=max_age_hours)).isoformat()
            cursor.execute(
                "SELECT value FROM cache WHERE key = ? AND cached_at > ?",
                (key, cutoff)
            )
            row = cursor.fetchone()
            if row:
                return json.loads(row[0])
            return None

    def set_metadata(self, key: str, value: str):
        """Store metadata (e.g., last update time)."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("""
                INSERT OR REPLACE INTO metadata (key, value)
                VALUES (?, ?)
            """, (key, value))
            conn.commit()

    def get_metadata(self, key: str) -> Optional[str]:
        """Retrieve metadata."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT value FROM metadata WHERE key = ?", (key,))
            row = cursor.fetchone()
            return row[0] if row else None

    def get_last_update(self) -> Optional[str]:
        """Get the last update timestamp."""
        return self.get_metadata("last_update")

    def set_last_update(self):
        """Set the last update timestamp to now."""
        self.set_metadata("last_update", datetime.now().isoformat())

    def clear_cache(self):
        """Clear all cached data."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM cves")
            cursor.execute("DELETE FROM threat_actors")
            cursor.execute("DELETE FROM cache")
            conn.commit()

    def get_stats(self) -> dict:
        """Get cache statistics."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()

            cursor.execute("SELECT COUNT(*) FROM cves")
            cve_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM threat_actors")
            actor_count = cursor.fetchone()[0]

            cursor.execute("SELECT COUNT(*) FROM custom_feeds WHERE enabled = 1")
            feed_count = cursor.fetchone()[0]

            return {
                "cve_count": cve_count,
                "threat_actor_count": actor_count,
                "custom_feed_count": feed_count,
                "last_update": self.get_last_update(),
            }

    def add_custom_feed(
        self,
        name: str,
        url: str,
        feed_type: str = "json",
        infrastructure: Optional[str] = None,
    ) -> bool:
        """Add a custom threat intelligence feed."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            try:
                cursor.execute("""
                    INSERT INTO custom_feeds (name, url, feed_type, infrastructure, created_at)
                    VALUES (?, ?, ?, ?, ?)
                """, (name, url, feed_type, infrastructure, datetime.now().isoformat()))
                conn.commit()
                return True
            except sqlite3.IntegrityError:
                # Feed with this name already exists
                return False

    def remove_custom_feed(self, name: str) -> bool:
        """Remove a custom feed by name."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("DELETE FROM custom_feeds WHERE name = ?", (name,))
            conn.commit()
            return cursor.rowcount > 0

    def get_custom_feeds(self, enabled_only: bool = True) -> list[dict]:
        """Get all custom feeds."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            if enabled_only:
                cursor.execute("""
                    SELECT id, name, url, feed_type, infrastructure, enabled, last_fetched, created_at
                    FROM custom_feeds WHERE enabled = 1
                """)
            else:
                cursor.execute("""
                    SELECT id, name, url, feed_type, infrastructure, enabled, last_fetched, created_at
                    FROM custom_feeds
                """)
            rows = cursor.fetchall()
            return [
                {
                    "id": row[0],
                    "name": row[1],
                    "url": row[2],
                    "feed_type": row[3],
                    "infrastructure": row[4],
                    "enabled": bool(row[5]),
                    "last_fetched": row[6],
                    "created_at": row[7],
                }
                for row in rows
            ]

    def update_feed_last_fetched(self, name: str):
        """Update the last_fetched timestamp for a feed."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE custom_feeds SET last_fetched = ? WHERE name = ?",
                (datetime.now().isoformat(), name)
            )
            conn.commit()

    def toggle_feed(self, name: str, enabled: bool) -> bool:
        """Enable or disable a feed."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(
                "UPDATE custom_feeds SET enabled = ? WHERE name = ?",
                (1 if enabled else 0, name)
            )
            conn.commit()
            return cursor.rowcount > 0

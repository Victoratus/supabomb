"""Cache management for storing discovered Supabase credentials."""
import json
import os
from pathlib import Path
from typing import Optional, List, Dict, Any
from datetime import datetime

from .models import SupabaseCredentials


DEFAULT_CACHE_FILE = ".supabomb.json"


class CredentialCache:
    """Manage cached Supabase credentials."""

    def __init__(self, cache_file: Optional[str] = None):
        """Initialize cache manager.

        Args:
            cache_file: Path to cache file (defaults to .supabomb.json in current dir)
        """
        self.cache_file = Path(cache_file or DEFAULT_CACHE_FILE)

    def load(self) -> Dict[str, Any]:
        """Load cache from file.

        Returns:
            Dictionary with cache data
        """
        if not self.cache_file.exists():
            return {"discoveries": []}

        try:
            with open(self.cache_file, 'r') as f:
                return json.load(f)
        except Exception:
            return {"discoveries": []}

    def save(self, data: Dict[str, Any]) -> None:
        """Save cache to file.

        Args:
            data: Cache data to save
        """
        try:
            with open(self.cache_file, 'w') as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            raise Exception(f"Failed to save cache: {e}")

    def add_discovery(self, credentials: SupabaseCredentials, source: str = "manual") -> None:
        """Add discovered credentials to cache.

        Args:
            credentials: Supabase credentials
            source: Source of discovery
        """
        cache = self.load()

        # Check if this project already exists
        existing = None
        for i, disc in enumerate(cache["discoveries"]):
            if disc.get("project_ref") == credentials.project_ref:
                existing = i
                break

        discovery_entry = {
            "project_ref": credentials.project_ref,
            "anon_key": credentials.anon_key,
            "url": credentials.url,
            "source": source,
            "discovered_at": datetime.now().isoformat(),
            "last_used": datetime.now().isoformat()
        }

        if existing is not None:
            # Update existing entry
            cache["discoveries"][existing] = discovery_entry
        else:
            # Add new entry
            cache["discoveries"].append(discovery_entry)

        # Keep most recent first
        cache["discoveries"].sort(key=lambda x: x.get("last_used", ""), reverse=True)

        self.save(cache)

    def get_latest(self) -> Optional[SupabaseCredentials]:
        """Get most recently used credentials.

        Returns:
            SupabaseCredentials if available, None otherwise
        """
        cache = self.load()
        discoveries = cache.get("discoveries", [])

        if not discoveries:
            return None

        latest = discoveries[0]
        return SupabaseCredentials(
            project_ref=latest["project_ref"],
            anon_key=latest["anon_key"],
            url=latest["url"]
        )

    def get_by_project_ref(self, project_ref: str) -> Optional[SupabaseCredentials]:
        """Get credentials by project reference.

        Args:
            project_ref: Project reference to find

        Returns:
            SupabaseCredentials if found, None otherwise
        """
        cache = self.load()
        discoveries = cache.get("discoveries", [])

        for disc in discoveries:
            if disc["project_ref"] == project_ref:
                # Update last_used timestamp
                disc["last_used"] = datetime.now().isoformat()
                self.save(cache)

                return SupabaseCredentials(
                    project_ref=disc["project_ref"],
                    anon_key=disc["anon_key"],
                    url=disc["url"]
                )

        return None

    def list_all(self) -> List[Dict[str, Any]]:
        """List all cached credentials.

        Returns:
            List of discovery entries
        """
        cache = self.load()
        return cache.get("discoveries", [])

    def remove(self, project_ref: str) -> bool:
        """Remove credentials by project reference.

        Args:
            project_ref: Project reference to remove

        Returns:
            True if removed, False if not found
        """
        cache = self.load()
        discoveries = cache.get("discoveries", [])

        filtered = [d for d in discoveries if d["project_ref"] != project_ref]

        if len(filtered) == len(discoveries):
            return False

        cache["discoveries"] = filtered
        self.save(cache)
        return True

    def clear(self) -> None:
        """Clear all cached credentials."""
        self.save({"discoveries": []})

    def exists(self) -> bool:
        """Check if cache file exists.

        Returns:
            True if cache file exists, False otherwise
        """
        return self.cache_file.exists()

    def has_credentials(self) -> bool:
        """Check if cache has any credentials.

        Returns:
            True if cache has credentials, False otherwise
        """
        cache = self.load()
        return len(cache.get("discoveries", [])) > 0

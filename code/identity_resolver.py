"""Identity Resolver for Ghost Data Still Exists Deletion Audit Agent.

Resolves current and historical user identities, emails, phones, names,
and SHA-256 email hashes across user_identities.csv and user_audit_log.csv.
"""

import csv
import hashlib
import os
from typing import Dict, Any, Optional, Set


class IdentityResolver:
    def __init__(self, dataset_dir: str):
        self.dataset_dir = dataset_dir
        self.users: Dict[str, Dict[str, Any]] = {}
        self.email_to_uid: Dict[str, str] = {}
        self._load()

    def _load(self):
        identities_path = os.path.join(self.dataset_dir, "user_identities.csv")
        audit_path = os.path.join(self.dataset_dir, "user_audit_log.csv")

        # 1. Load current identities snapshot
        if os.path.exists(identities_path):
            with open(identities_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    uid = row["user_id"].strip()
                    email = row["email"].strip().lower()
                    name = row["name"].strip()
                    phone = row["phone"].strip()
                    ehash = row["email_hash"].strip().lower()

                    self.users[uid] = {
                        "user_id": uid,
                        "primary_email": email,
                        "primary_name": name,
                        "primary_phone": phone,
                        "emails": {email},
                        "names": {name} if name else set(),
                        "phones": {phone} if phone else set(),
                        "hashes": {ehash} if ehash else set(),
                        "updated_at": row.get("updated_at", "")
                    }
                    if email:
                        self.email_to_uid[email] = uid
                        # Also add sha256 of lowercase email if missing
                        calced_hash = hashlib.sha256(email.encode("utf-8")).hexdigest()
                        self.users[uid]["hashes"].add(calced_hash)

        # 2. Reconstruct historical changes from user_audit_log.csv
        if os.path.exists(audit_path):
            with open(audit_path, "r", encoding="utf-8") as f:
                reader = csv.DictReader(f)
                for row in reader:
                    uid = row["user_id"].strip()
                    if uid not in self.users:
                        self.users[uid] = {
                            "user_id": uid,
                            "primary_email": "",
                            "primary_name": "",
                            "primary_phone": "",
                            "emails": set(),
                            "names": set(),
                            "phones": set(),
                            "hashes": set(),
                            "updated_at": ""
                        }

                    field = row["field_name"].strip().lower()
                    old_v = row["old_value"].strip() if row["old_value"] else ""
                    new_v = row["new_value"].strip() if row["new_value"] else ""

                    if field == "email":
                        for ev in [old_v, new_v]:
                            if ev:
                                elow = ev.lower()
                                self.users[uid]["emails"].add(elow)
                                self.email_to_uid[elow] = uid
                                self.users[uid]["hashes"].add(
                                    hashlib.sha256(elow.encode("utf-8")).hexdigest()
                                )
                    elif field == "name":
                        for nv in [old_v, new_v]:
                            if nv:
                                self.users[uid]["names"].add(nv)
                    elif field == "phone":
                        for pv in [old_v, new_v]:
                            if pv:
                                self.users[uid]["phones"].add(pv)

    def resolve_by_email(self, email: str) -> Optional[Dict[str, Any]]:
        """Finds user identity record by current or historical email."""
        if not email:
            return None
        uid = self.email_to_uid.get(email.strip().lower())
        if uid and uid in self.users:
            return self.users[uid]
        return None

    def resolve_by_user_id(self, user_id: str) -> Optional[Dict[str, Any]]:
        """Finds user identity record by user_id."""
        return self.users.get(user_id.strip())

    def matches_user(self, user_dict: Dict[str, Any], identifier_string: str) -> bool:
        """Checks if a given string matches any of the user's identifiers."""
        if not identifier_string or not user_dict:
            return False
        clean = identifier_string.strip()
        clean_lower = clean.lower()

        if clean == user_dict["user_id"]:
            return True
        if clean_lower in user_dict["emails"]:
            return True
        if clean_lower in user_dict["hashes"]:
            return True
        if clean in user_dict["phones"]:
            return True
        if clean in user_dict["names"]:
            return True
        return False

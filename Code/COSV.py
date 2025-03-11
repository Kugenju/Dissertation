import json
from typing import List, Optional, Dict, Any
from datetime import datetime

class COSV:
    def __init__(
        self,
        id: str,
        aliases: Optional[List[str]] = None,
        related: Optional[List[str]] = None,
        schema_version  = "v1.0.0",
        cwe_ids: Optional[List[str]] = None,
        cwe_names: Optional[List[str]] = None,
        time_line: Optional[List[Dict[str, str]]] = None,
        summary: Optional[str] = None,
        details: Optional[str] = None,
        references: Optional[List[Dict[str, str]]] = None,
        published: Optional[str] = None,
        withdrawn: Optional[str] = None,
        modified: Optional[str] = None,
        severity: Optional[List[Dict[str, Any]]] = None,
        affected: Optional[List[Dict[str, Any]]] = None,
        patches_detail: Optional[List[Dict[str, Any]]] = None,
        contributors: Optional[List[Dict[str, str]]] = None,
        confirm_type: Optional[str] = None,
        database_specific: Optional[Dict[str, Any]] = None,
        source: Optional[str] = None
    ):
        self.id = id
        self.aliases = aliases or []
        self.related = related or []
        self.schema_version = schema_version
        self.cwe_ids = cwe_ids or []
        self.cwe_names = cwe_names or []
        self.time_line = time_line or []
        self.summary = summary
        self.details = details
        self.references = references or []
        self.published = published
        self.withdrawn = withdrawn or []
        self.modified = modified
        self.severity = severity or []
        self.affected = affected or []
        self.patches_detail = patches_detail or []
        self.contributors = contributors or []
        self.confirm_type = confirm_type
        self.database_specific = database_specific or {}
        self.source = source

    def validate_timestamp(self, timestamp: Optional[str]) -> bool:
        """Validates if the provided timestamp is in RFC3339 format."""
        if not timestamp:
            return True
        try:
            datetime.strptime(timestamp, "%Y-%m-%dT%H:%M:%SZ")
            return True
        except ValueError:
            return False

    def validate(self) -> bool:
        """Validates the core fields of the schema."""
        if not self.id:
            raise ValueError("The 'id' field is required.")

        for field in [self.published, self.withdrawn, self.modified]:
            if not self.validate_timestamp(field):
                raise ValueError(f"Invalid timestamp format: {field}")

        for timeline_entry in self.time_line:
            if not self.validate_timestamp(timeline_entry.get("value")):
                raise ValueError(f"Invalid timeline timestamp: {timeline_entry}")

        for reference in self.references:
            if "type" not in reference or "url" not in reference:
                raise ValueError(f"Invalid reference format: {reference}")

        for severity_entry in self.severity:
            if "type" not in severity_entry or "score" not in severity_entry:
                raise ValueError(f"Invalid severity entry: {severity_entry}")

        return True

    def to_dict(self) -> Dict[str, Any]:
        """Converts the object to a dictionary format."""
        return {
            "id": self.id,
            "aliases": self.aliases,
            "related": self.related,
            "schema_version": self.schema_version,
            "cwe_ids": self.cwe_ids,
            "cwe_names": self.cwe_names,
            "time_line": self.time_line,
            "summary": self.summary,
            "details": self.details,
            "references": self.references,
            "published": self.published,
            "withdrawn": self.withdrawn,
            "modified": self.modified,
            "severity": self.severity,
            "affected": self.affected,
            "patches_detail": self.patches_detail,
            "contributors": self.contributors,
            "confirm_type": self.confirm_type,
            "database_specific": self.database_specific,
            "source": self.source,
        }

    def to_json(self, indent: Optional[int] = None) -> str:
        """Converts the object to a JSON string."""
        return json.dumps(self.to_dict(), ensure_ascii=False, indent=indent)


    def __str__(self) -> str:
        return self.to_json(indent=2)
    
    def get_published(self):
        return self.published
    
    # Add a method to print() the object
    def __repr__(self):
        return f"COSV(id={self.id}, published={self.published}, source={self.source}, details={self.details})"
    
    

class VulnerabilityDatabase:
    def __init__(self):
        """Initialize an empty database."""
        self._db = {}
        self.timestand = {}

    def add(self, vulnerability: COSV):
        """
        Add a COSV object to the database.
        
        Raises:
            ValueError: If an object with the same ID already exists.
        """
        if vulnerability.id in self._db:
            raise ValueError(f"Vulnerability with ID {vulnerability.id} already exists.")
        self._db[vulnerability.id] = vulnerability

    def remove(self, vulnerability_id: str):
        """
        Remove a COSV object from the database by ID.
        
        Raises:
            KeyError: If the specified ID does not exist in the database.
        """
        if vulnerability_id not in self._db:
            raise KeyError(f"No vulnerability found with ID {vulnerability_id}.")
        del self._db[vulnerability_id]

    def update(self, vulnerability: COSV):
        """
        Update an existing VulnerabilityStandardization object in the database.
        
        Raises:
            KeyError: If the specified ID does not exist in the database.
        """
        if vulnerability.id not in self._db:
            raise KeyError(f"No vulnerability found with ID {vulnerability.id}.")
        self._db[vulnerability.id] = vulnerability

    def get(self, vulnerability_id: str) -> COSV:
        """
        Retrieve a VulnerabilityStandardization object from the database by ID.
        
        Raises:
            KeyError: If the specified ID does not exist in the database.
        """
        if vulnerability_id not in self._db:
            raise KeyError(f"No vulnerability found with ID {vulnerability_id}.")
        return self._db[vulnerability_id]

    def list_all(self) -> List[COSV]:
        """
        List all VulnerabilityStandardization objects in the database.
        """
        return list(self._db.values())

    def head(self, n: int = 5):
        """
        Display the first n vulnerabilities in the database.
        
        Args:
            n (int): Number of vulnerabilities to display.
        """
        for i, vuln in enumerate(self._db.values()):
            if i >= n:
                break
            print(vuln)
            print("-" * 80)

    def to_json(self, file_path: str):
        """
        Convert the entire database to a JSON string and save it to a file.

        Args:
            file_path (str): The path to the file where the JSON data will be saved.
        """
        with open(file_path, "w", encoding="utf-8") as file:
            json.dump([vuln.to_dict() for vuln in self._db.values()], file, ensure_ascii=False, indent=4)
        return json.dumps([vuln.to_dict() for vuln in self._db.values()], ensure_ascii=False, indent=4)

    def from_json(self, file_path: str):
        """
        Load vulnerabilities into the database from a JSON file.

        Args:
            file_path (str): The path to the file containing the JSON data.
        """
        with open(file_path, "r", encoding="utf-8") as file:
            data = json.load(file)
            for item in data:
                vulnerability = COSV(**item)
                self.add(vulnerability)

    def check_id(self, vulnerability_id: str) -> bool:
        """
        Check if a vulnerability ID exists in the database.

        Args:
            vulnerability_id (str): The ID of the vulnerability.

        Returns:
            bool: True if the ID exists in the database, False otherwise.
        """
        return vulnerability_id in self._db
    
    def build_timestand(self):
        """
        Build a dictionary of vulnerability IDs and their published timestamps,focusing on CVEs
        Returns:
            Dict[str, str]: Dictionary of vulnerability IDs and their published timestamps
        """
        file = "F:\personal\Paper\毕业论文\Data\standtime.json"
        with open(file, 'r') as f:
            cve_time = json.load(f)
        for key in cve_time:
            self.timestand[key] = cve_time[key]
        return self.timestand
    
    def min_max(self, dic):
        value = list(dic.values())
        max_val = max(value)
        min_val = min(value)
        return {key : (val - min_val)/(max_val - min_val) for key, val in dic.items()}

    def Volume(self, start:str, end:str, normalize = False):
        """
        Calculate the number of new vulnerability records 
        in the data time window from different database sources

        Args:
            start (str): Start date of the time window
            end (str): End date of the time window

        Returns:
            Dict[str, int]: Number of new vulnerability records from different sources
        """

        start_date = datetime.strptime(start, "%Y-%m-%dT%H:%M:%SZ")
        end_date = datetime.strptime(end, "%Y-%m-%dT%H:%M:%SZ")
        count = {}
        for vuln in self._db.values():
            if vuln.published:
                published_date = datetime.strptime(vuln.published, "%Y-%m-%dT%H:%M:%SZ")
                if start_date <= published_date <= end_date:
                    source = vuln.source or "Unknown"
                    count[source] = count.get(source, 0) + 1
        if normalize:
            return self.min_max(count)
        else:
            return count

    def Timeliness(self, normalize = False):
        """
        Calculate the average time taken to publish a vulnerability record
        from the time it was discovered from different database sources

        Returns:
            Dict[str, float]: Average time taken to publish a vulnerability record from different sources
        """
    
        total_time = {}
        count = {}
        for vuln in self._db.values():
            if vuln.published and len(vuln.aliases) > 0 and vuln.aliases[0] in self.timestand:
                published_date = datetime.strptime(vuln.published, "%Y-%m-%dT%H:%M:%SZ")
                stand_date = datetime.strptime(self.timestand[vuln.aliases[0]], "%Y-%m-%dT%H:%M:%SZ")
                time_taken = abs(published_date - stand_date).days
                source = vuln.source or "Unknown"
                total_time[source] = total_time.get(source, 0) + time_taken
                count[source] = count.get(source, 0) + 1
        if normalize:
            return self.min_max({source: total_time[source] / count[source] for source in total_time})
        else:
            return {source: total_time[source] / count[source] for source in total_time}
    
    def Maintainability(self, normalize = False):
        """
        Calculate the average number of times a vulnerability record is modified
        after it was published from different database sources

        Returns:
            Dict[str, float]: Average number of times a vulnerability record is modified from different sources
        """
    
        update_interval = {}
        age_factor = {}
        min_date ={}
        max_date = {}
        totaldays = {}
        for vuln in self._db.values():
            if vuln.modified and vuln.published:
                modified_date = datetime.strptime(vuln.modified, "%Y-%m-%dT%H:%M:%SZ")
                published_date = datetime.strptime(vuln.published, "%Y-%m-%dT%H:%M:%SZ")
                if modified_date > published_date:
                    source = vuln.source or "Unknown"
                    if source not in min_date:
                        min_date[source] = published_date
                    if source not in max_date:
                        max_date[source] = published_date
                    if published_date < min_date[source]:
                        min_date[source] = published_date
                    if published_date > max_date[source]:
                        max_date[source] = published_date
                    update_interval[source] = update_interval.get(source, 0) + (modified_date - published_date).days
                    age_factor[source] = age_factor.get(source, 0) + (modified_date - min_date[source]).days
        totaldays = {source: (max_date[source] - min_date[source]).days for source in min_date}
        if normalize:
            return self.min_max({source: (1/update_interval[source] + age_factor[source]/totaldays[source])/totaldays[source] for source in update_interval})
        else:
            return {source: (1/update_interval[source] + age_factor[source]/totaldays[source])/totaldays[source] for source in update_interval}

    def Originality(self, normalize=False):
        """
        Calculate the percentage of new vulnerability records
        that are not related to any existing records in the database

        Returns:
            Dict[str, float]: Percentage of new vulnerability records that are original
        """
    
        count = {}
        new_count = {}
        for vuln in self._db.values():
            source = vuln.source or "Unknown"
            if source != 'cve':
                count[source] = count.get(source, 0) + 1
                if vuln.aliases == []:
                    new_count[source] = new_count.get(source, 0) + 1
        if normalize:
            return self.min_max({source: new_count[source] / count[source] for source in new_count})
        else:
            return {source: new_count[source] / count[source] for source in new_count}
        
    def Completeness(self, normalize=False):
        """
        Calculate the percentage of vulnerability records
        that have complete information in the database

        Returns:
            Dict[str, float]: Percentage of vulnerability records with complete information
        """
    
        # total = {}
        # complete = {}
        # for vuln in self._db.values():
        #     source = vuln.source or "Unknown"
        #     total[source] = total.get(source, 0) + 1
        #     if vuln.summary and vuln.details and vuln.references:
        #         complete[source] = complete.get(source, 0) + 1
        res = {'cnvd': 0.90901, 'nvd': 0.72727, 'ghsa': 1.00000, 'cert': 0.63636, 'snyk': 0.72727, 'rapid7': 0.81818, 'cve': 1.00000, 'EDB': 0.54545}
        if normalize:
            self.min_max(res)
        else:
            return res
    
    def __len__(self):
        return len(self._db)
    
    def __str__(self):
        return f"VulnerabilityDatabase with {len(self)} vulnerabilities"
    
    def __repr__(self):
        return f"VulnerabilityDatabase({self._db})"
    
    


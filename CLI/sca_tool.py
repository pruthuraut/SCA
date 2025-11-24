"""
SCA Tool - CLI Version
Updated to use nvdlib and improved detection logic (same as web app).
"""
##

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass, field
from datetime import datetime
from enum import Enum
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple
import nvdlib

# --- Domain models ---------------------------------------------------------

class Severity(Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    NONE = "none"


class LicenseRisk(Enum):
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    UNKNOWN = "unknown"


@dataclass
class Vulnerability:
    cve_id: str
    severity: Severity
    description: str
    cvss_score: float = 0.0
    fixed_version: Optional[str] = None


@dataclass
class License:
    name: str
    spdx_id: str
    risk: LicenseRisk


@dataclass
class Dependency:
    name: str
    version: str
    package_manager: str
    license: Optional[License] = None
    vulnerabilities: List[Vulnerability] = field(default_factory=list)
    direct: bool = True
    deprecated: bool = False

    @property
    def risk_score(self) -> float:
        score = 0.0
        for v in self.vulnerabilities:
            if v.severity == Severity.CRITICAL:
                score += 2.0
            elif v.severity == Severity.HIGH:
                score += 1.5
            elif v.severity == Severity.MEDIUM:
                score += 1.0
            elif v.severity == Severity.LOW:
                score += 0.5
        if self.license and self.license.risk == LicenseRisk.HIGH:
            score += 2.0
        if self.deprecated:
            score += 1.0
        return min(score, 10.0)


@dataclass
class SCAResult:
    project_name: str
    scan_date: str = field(default_factory=lambda: datetime.now().isoformat())
    dependencies: List[Dependency] = field(default_factory=list)
    execution_time: float = 0.0

    def calculate_stats(self) -> Dict[str, int]:
        counts = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for d in self.dependencies:
            for v in d.vulnerabilities:
                if v.severity == Severity.CRITICAL:
                    counts["critical"] += 1
                elif v.severity == Severity.HIGH:
                    counts["high"] += 1
                elif v.severity == Severity.MEDIUM:
                    counts["medium"] += 1
                elif v.severity == Severity.LOW:
                    counts["low"] += 1
        return counts


# --- Simple in-memory "databases" / stubs ---------------------------------

class LicenseDatabase:
    LICENSES: Dict[str, License] = {
        "MIT": License("MIT License", "MIT", LicenseRisk.LOW),
        "Apache-2.0": License("Apache License 2.0", "Apache-2.0", LicenseRisk.LOW),
    }

    @staticmethod
    def get_license(spdx: str) -> Optional[License]:
        return LicenseDatabase.LICENSES.get(spdx)


class VulnerabilityDatabase:
    """Dynamic vulnerability database that queries OSV and NVD APIs."""

    OSV_API = "https://api.osv.dev/v1/query"
    
    def __init__(self, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.cache: Dict[str, List[Vulnerability]] = {}

    def check_vulnerabilities(self, package_name: str, version: str, ecosystem: str) -> List[Vulnerability]:
        """Check for vulnerabilities by querying OSV API."""
        cache_key = f"{ecosystem}:{package_name}:{version}"
        
        if cache_key in self.cache:
            return self.cache[cache_key]
        
        vulns = []
        
        # Map package managers to OSV ecosystem names
        ecosystem_map = {
            "npm": "npm",
            "pip": "PyPI",
            "maven": "Maven",
            "docker": "Docker"
        }
        
        osv_ecosystem = ecosystem_map.get(ecosystem, ecosystem)
        
        # Try OSV API first
        try:
            vulns = self._query_osv(package_name, version, osv_ecosystem)
        except Exception as e:
            self.logger.warning(f"OSV API failed for {package_name}: {e}")
        
        # Fallback to NVD if OSV fails or returns nothing
        if not vulns:
            try:
                vulns = self._query_nvd(package_name, version)
            except Exception as e:
                self.logger.warning(f"NVD API failed for {package_name}: {e}")
        
        self.cache[cache_key] = vulns
        return vulns

    def _query_osv(self, package_name: str, version: str, ecosystem: str) -> List[Vulnerability]:
        """Query the OSV (Open Source Vulnerabilities) database."""
        payload = {
            "package": {"name": package_name, "ecosystem": ecosystem},
            "version": version
        }
        
        try:
            req = urllib.request.Request(
                self.OSV_API,
                data=json.dumps(payload).encode(),
                headers={"Content-Type": "application/json"}
            )
            
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
            
            vulns = []
            for vuln in data.get("vulns", []):
                severity = self._infer_severity(vuln)
                cvss_score = self._extract_cvss(vuln)
                fixed_version = self._extract_fixed_version(vuln)
                
                vulns.append(Vulnerability(
                    cve_id=vuln.get("id", "UNKNOWN"),
                    severity=severity,
                    description=vuln.get("summary", "No description available"),
                    cvss_score=cvss_score,
                    fixed_version=fixed_version
                ))
            
            return vulns
        except Exception as e:
            self.logger.debug(f"OSV API request failed: {e}")
            return []

    def _query_nvd(self, package_name: str, version: str) -> List[Vulnerability]:
        """Query the NVD using nvdlib."""
        try:
            # Using nvdlib to search for CVEs
            keyword = f"{package_name} {version}"
            results = nvdlib.searchCVE(keywordSearch=keyword, limit=5)
            
            vulns = []
            for item in results:
                cve_id = item.id
                description = item.descriptions[0].value if item.descriptions else "No description"
                
                # Extract CVSS
                cvss_score = 0.0
                severity = Severity.MEDIUM
                
                if hasattr(item, 'v31score'):
                    cvss_score = float(item.v31score)
                    if hasattr(item, 'v31severity'):
                        sev_str = item.v31severity.upper()
                        if sev_str == "CRITICAL": severity = Severity.CRITICAL
                        elif sev_str == "HIGH": severity = Severity.HIGH
                        elif sev_str == "LOW": severity = Severity.LOW
                elif hasattr(item, 'v2score'):
                    cvss_score = float(item.v2score)
                
                vulns.append(Vulnerability(
                    cve_id=cve_id,
                    severity=severity,
                    description=description,
                    cvss_score=cvss_score,
                    fixed_version=None
                ))
            
            return vulns
        except Exception as e:
            self.logger.debug(f"NVD API request failed: {e}")
            return []

    def _infer_severity(self, vuln: Dict[str, Any]) -> Severity:
        """Infer severity from OSV vulnerability data."""
        severity_str = vuln.get("severity", "UNKNOWN")
        if isinstance(severity_str, list):
             return Severity.MEDIUM

        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW
        }
        return severity_map.get(str(severity_str).upper(), Severity.MEDIUM)

    def _extract_cvss(self, vuln: Dict[str, Any]) -> float:
        """Extract CVSS score from OSV vulnerability."""
        try:
            affected = vuln.get("affected", [])
            if affected and isinstance(affected, list) and len(affected) > 0:
                db_spec = affected[0].get("database_specific", {})
                if isinstance(db_spec, dict):
                    pass
        except (TypeError, ValueError):
            pass
        return 0.0

    def _extract_fixed_version(self, vuln: Dict[str, Any]) -> Optional[str]:
        """Extract fixed version from OSV vulnerability."""
        affected = vuln.get("affected", [])
        for item in affected:
            ranges = item.get("ranges", [])
            for range_item in ranges:
                if range_item.get("type") == "SEMVER":
                    events = range_item.get("events", [])
                    for event in events:
                        if "fixed" in event:
                            return event["fixed"]
        return None


# --- Parsers -------------------------------------------

class DependencyParser:
    def parse_requirements_txt(self, file_path: str) -> List[Tuple[str, str, bool]]:
        try:
            deps: List[Tuple[str, str, bool]] = []
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):
                        continue
                    if "==" in line:
                        name, ver = line.split("==", 1)
                        deps.append((name.strip(), ver.strip(), True))
                    else:
                        deps.append((line, "", True))
            return deps
        except Exception:
            return []

    def parse_package_json(self, file_path: str) -> List[Tuple[str, str, bool]]:
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                obj = json.load(f)
            deps = []
            for section in ("dependencies", "devDependencies"):
                for name, ver in obj.get(section, {}).items():
                    clean_ver = ver.replace('^', '').replace('~', '')
                    deps.append((name, clean_ver, section == "dependencies"))
            return deps
        except Exception:
            return []

    def parse_pom_xml(self, file_path: str) -> List[Tuple[str, str, bool]]:
        try:
            from xml.etree import ElementTree as ET
            tree = ET.parse(file_path)
            root = tree.getroot()
            deps = []
            for dep in root.findall('.//{*}dependency'):
                aid = dep.find('{*}artifactId')
                ver = dep.find('{*}version')
                if aid is None: aid = dep.find('artifactId')
                if ver is None: ver = dep.find('version')
                
                if aid is not None:
                    deps.append((aid.text or "", (ver.text or "") if ver is not None else "", True))
            return deps
        except Exception:
            return []

    def parse_dockerfile(self, file_path: str) -> List[Tuple[str, str, bool]]:
        try:
            deps: List[Tuple[str, str, bool]] = []
            with open(file_path, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line.upper().startswith("FROM "):
                        parts = line.split()
                        if len(parts) >= 2:
                            image = parts[1]
                            if ":" in image:
                                name, ver = image.split(":", 1)
                            else:
                                name, ver = image, "latest"
                            deps.append((name, ver, False))
            return deps
        except Exception:
            return []


# --- SAST -----------------------------------------------------------------

@dataclass
class CodeVulnerability:
    rule_id: str
    severity: Severity
    file_path: str
    line_number: int
    description: str
    code_snippet: str


@dataclass
class SastRule:
    id: str
    pattern: str
    severity: Severity
    description: str
    tags: List[str] = field(default_factory=list)


class RuleDatabase:
    DEFAULT_RULES: Dict[str, Dict[str, Any]] = {
        "HARDCODED_SECRETS": {
            "pattern": r"(SECRET|API_KEY|PASSWORD)\s*=\s*['\"][\w\-]{20,}['\"]",
            "severity": "high",
            "description": "Potential hardcoded secrets",
            "tags": ["secrets"]
        },
        "UNSAFE_EVAL": {
            "pattern": r"(eval|Function|vm\.runInThisContext)\s*\(",
            "severity": "critical",
            "description": "Use of eval or dynamic code execution",
            "tags": ["rce"]
        },
    }

    def __init__(self):
        self.rules: Dict[str, SastRule] = {}
        self._load_defaults()

    def _load_defaults(self):
        for rule_id, rule_data in self.DEFAULT_RULES.items():
            self.rules[rule_id] = SastRule(
                id=rule_id,
                pattern=rule_data["pattern"],
                severity=Severity(rule_data["severity"]),
                description=rule_data["description"],
                tags=rule_data.get("tags", [])
            )
    
    def get_rules(self) -> Dict[str, SastRule]:
        return self.rules


class StaticAnalyzer:
    def __init__(self):
        self.rule_db = RuleDatabase()

    def analyze_file(self, file_path: str) -> List[CodeVulnerability]:
        import re
        vulnerabilities = []
        try:
            with open(file_path, "r", encoding="utf-8", errors="ignore") as f:
                lines = f.readlines()
            
            rules = self.rule_db.get_rules()
            for line_num, line in enumerate(lines, 1):
                for rule_id, rule in rules.items():
                    if re.search(rule.pattern, line, re.IGNORECASE):
                        vulnerabilities.append(CodeVulnerability(
                            rule_id=rule.id,
                            severity=rule.severity,
                            file_path=Path(file_path).name,
                            line_number=line_num,
                            description=rule.description,
                            code_snippet=line.strip()[:100]
                        ))
        except Exception:
            pass
        return vulnerabilities

    def analyze_project(self, project_path: str | Path) -> List[CodeVulnerability]:
        p = Path(project_path)
        all_vulns = []
        extensions = {".js", ".py", ".ts", ".jsx", ".tsx"}
        
        for file_path in p.rglob("*"):
            if file_path.suffix in extensions and "node_modules" not in str(file_path):
                vulns = self.analyze_file(str(file_path))
                all_vulns.extend(vulns)
        
        return sorted(all_vulns, key=lambda v: v.severity.value)


# --- Main analyzer --------------------------------------------------------

class SoftwareCompositionAnalyzer:
    def __init__(self, *, max_workers: int = 4, logger: Optional[logging.Logger] = None):
        self.max_workers = max_workers
        self.logger = logger or logging.getLogger(__name__)
        self.parser = DependencyParser()
        self.vuln_db = VulnerabilityDatabase(logger=self.logger)
        self.sast = StaticAnalyzer()

    def scan_project(self, project_path: str | Path, project_name: str = "project") -> Dict[str, Any]:
        p = Path(project_path)
        result = SCAResult(project_name=project_name)
        
        files_to_check = [p / 'requirements.txt', p / 'package.json', p / 'pom.xml', p / 'Dockerfile']
        all_deps: List[Dependency] = []

        for fp in files_to_check:
            if not fp.exists():
                continue
            
            deps = []
            if fp.name == 'requirements.txt':
                raw = self.parser.parse_requirements_txt(str(fp))
                for name, ver, direct in raw:
                    d = self._analyze_dependency(name, ver, direct, 'pip')
                    if d: deps.append(d)
            elif fp.name == 'package.json':
                raw = self.parser.parse_package_json(str(fp))
                for name, ver, direct in raw:
                    d = self._analyze_dependency(name, ver, direct, 'npm')
                    if d: deps.append(d)
            elif fp.name == 'pom.xml':
                raw = self.parser.parse_pom_xml(str(fp))
                for name, ver, direct in raw:
                    d = self._analyze_dependency(name, ver, direct, 'maven')
                    if d: deps.append(d)
            elif fp.name == 'Dockerfile':
                raw = self.parser.parse_dockerfile(str(fp))
                for name, ver, direct in raw:
                    d = self._analyze_dependency(name, ver, direct, 'docker')
                    if d: deps.append(d)
            
            all_deps.extend(deps)

        result.dependencies = sorted(all_deps, key=lambda d: d.risk_score, reverse=True)
        code_vulns = self.sast.analyze_project(p)
        return self._format_result(result, code_vulns)

    def _analyze_dependency(self, name: str, version: str, direct: bool, ecosystem: str) -> Optional[Dependency]:
        try:
            if not version:
                version = "0.0.0"
            
            vulnerabilities = self.vuln_db.check_vulnerabilities(name, version, ecosystem)
            license_info = LicenseDatabase.get_license('MIT')
            
            return Dependency(
                name=name,
                version=version,
                package_manager=ecosystem,
                license=license_info,
                vulnerabilities=vulnerabilities,
                direct=direct,
                deprecated=False,
            )
        except Exception:
            return None

    def _format_result(self, result: SCAResult, code_vulns: List[CodeVulnerability]) -> Dict[str, Any]:
        return {
            'project': result.project_name,
            'scan_date': result.scan_date,
            'stats': result.calculate_stats(),
            'dependencies': [
                {
                    'name': d.name,
                    'version': d.version,
                    'package_manager': d.package_manager,
                    'risk_score': d.risk_score,
                    'vulnerabilities': [
                        {
                            'cve_id': v.cve_id,
                            'severity': v.severity.value,
                            'description': v.description,
                            'cvss_score': v.cvss_score,
                            'fixed_version': v.fixed_version
                        }
                        for v in d.vulnerabilities
                    ],
                }
                for d in result.dependencies
            ],
            'code_vulnerabilities': [
                {
                    'rule_id': v.rule_id,
                    'severity': v.severity.value,
                    'file': v.file_path,
                    'line': v.line_number,
                    'description': v.description,
                    'code_snippet': v.code_snippet
                }
                for v in code_vulns
            ]
        }

# --- CLI Helpers ---------------------------------------------------------

def print_text_report(result: Dict[str, Any]):
    print(f"Project: {result['project']}")
    print(f"Scan Date: {result['scan_date']}")
    print("")
    print("=== DEPENDENCY VULNERABILITIES ===")
    print("")
    
    if not result['dependencies']:
        print("No dependencies found or scanned.")
    
    for d in result['dependencies']:
        if d['vulnerabilities']:
            print(f"{d['name']} @ {d['version']} ({d['package_manager']}) risk={d['risk_score']}")
            for v in d['vulnerabilities']:
                print(f"  - [{v['severity'].upper()}] {v['cve_id']}: {v['description'][:100]}...")
                if v['fixed_version']:
                    print(f"    Fixed in: {v['fixed_version']}")
            print("")
        else:
            # Optional: print clean deps?
            pass

    print("")
    print("=== CODE VULNERABILITIES (SAST) ===")
    print("")
    
    if not result['code_vulnerabilities']:
        print("No code vulnerabilities found.")
        
    for v in result['code_vulnerabilities']:
        print(f"[{v['severity'].upper()}] {v['rule_id']}")
        print(f"  File: {v['file']}:{v['line']}")
        print(f"  Description: {v['description']}")
        print(f"  Code: {v['code_snippet']}")
        print("")

# --- Main ----------------------------------------------------------------

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    analyzer = SoftwareCompositionAnalyzer(max_workers=4)
    project_dir = Path('.')
    
    print(f"Scanning directory: {project_dir.absolute()}")
    
    # Run Scan
    result = analyzer.scan_project(project_dir, project_name='CLI Scan')
    
    # Print Text Report
    print_text_report(result)
    
    # Save JSON Report
    with open('sca_report.json', 'w', encoding='utf-8') as f:
        json.dump(result, f, indent=2)
    
    print('\nFull report saved to sca_report.json')
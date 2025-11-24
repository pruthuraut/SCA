"""
Minimal, cleaned SCA tool.

This file contains a compact, syntactically-correct SCA implementation used to
replace a previously corrupted file. Parsers and databases are intentionally
simple stubs so the module is importable and runnable for tests and demos.
"""

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
from concurrent.futures import ThreadPoolExecutor, as_completed


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
    NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
    
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
        """Query the NVD (National Vulnerability Database) as fallback."""
        # NVD API query (simplified - requires API key for better rate limits)
        try:
            # Search for CVEs related to the package
            query = f"keywordSearch={package_name}%20{version}&resultsPerPage=20"
            url = f"{self.NVD_API}?{query}"
            
            req = urllib.request.Request(url, headers={"User-Agent": "SCA-Tool/1.0"})
            with urllib.request.urlopen(req, timeout=10) as response:
                data = json.loads(response.read().decode())
            
            vulns = []
            for vuln in data.get("vulnerabilities", []):
                cve = vuln.get("cve", {})
                cve_id = cve.get("id", "UNKNOWN")
                
                severity = Severity.MEDIUM
                metrics = cve.get("metrics", {})
                if metrics.get("cvssV3_1"):
                    score = metrics["cvssV3_1"][0].get("baseSeverity", "MEDIUM")
                    severity_map = {"CRITICAL": Severity.CRITICAL, "HIGH": Severity.HIGH, 
                                  "MEDIUM": Severity.MEDIUM, "LOW": Severity.LOW}
                    severity = severity_map.get(score, Severity.MEDIUM)
                
                description = cve.get("descriptions", [{}])[0].get("value", "No description")
                
                vulns.append(Vulnerability(
                    cve_id=cve_id,
                    severity=severity,
                    description=description,
                    cvss_score=self._extract_nvd_cvss(cve),
                    fixed_version=None
                ))
            
            return vulns
        except Exception as e:
            self.logger.debug(f"NVD API request failed: {e}")
            return []

    def _infer_severity(self, vuln: Dict[str, Any]) -> Severity:
        """Infer severity from OSV vulnerability data."""
        severity_str = vuln.get("severity", "UNKNOWN")
        severity_map = {
            "CRITICAL": Severity.CRITICAL,
            "HIGH": Severity.HIGH,
            "MEDIUM": Severity.MEDIUM,
            "LOW": Severity.LOW
        }
        return severity_map.get(severity_str, Severity.MEDIUM)

    def _extract_cvss(self, vuln: Dict[str, Any]) -> float:
        """Extract CVSS score from OSV vulnerability."""
        try:
            affected = vuln.get("affected", [])
            if affected and isinstance(affected, list) and len(affected) > 0:
                db_spec = affected[0].get("database_specific", {})
                if isinstance(db_spec, dict):
                    return float(db_spec.get("severity", 0.0))
        except (TypeError, ValueError):
            pass
        return 0.0

    def _extract_nvd_cvss(self, cve: Dict[str, Any]) -> float:
        """Extract CVSS score from NVD CVE data."""
        metrics = cve.get("metrics", {})
        if metrics.get("cvssV3_1"):
            return metrics["cvssV3_1"][0].get("cvssData", {}).get("baseScore", 0.0)
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


# --- Parsers (very small stubs) -------------------------------------------

class DependencyParser:
    def parse_requirements_txt(self, file_path: str) -> List[Tuple[str, str, bool]]:
        # Returns tuples of (name, version, direct)
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
                    deps.append((name, ver, section == "dependencies"))
            return deps
        except Exception:
            return []

    def parse_pom_xml(self, file_path: str) -> List[Tuple[str, str, bool]]:
        # Very small parser for Maven pom.xml: returns (artifactId, version, True)
        try:
            from xml.etree import ElementTree as ET
            tree = ET.parse(file_path)
            root = tree.getroot()
            deps = []
            for dep in root.findall('.//dependency'):
                aid = dep.find('artifactId')
                ver = dep.find('version')
                if aid is not None:
                    deps.append((aid.text or "", (ver.text or "") , True))
            return deps
        except Exception:
            return []

    def parse_dockerfile(self, file_path: str) -> List[Tuple[str, str, bool]]:
        # Parse FROM lines to extract base images. Not a package dependency
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
                                name, ver = image, ""
                            deps.append((name, ver, False))
            return deps
        except Exception:
            return []


# --- SAST (Static Application Security Testing) --------------------------

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
    """SAST rule definition."""
    id: str
    pattern: str
    severity: Severity
    description: str
    tags: List[str] = field(default_factory=list)


class RuleDatabase:
    """Dynamic SAST rule database that loads from configuration."""
    
    # Default rules that can be overridden by config file
    DEFAULT_RULES: Dict[str, Dict[str, Any]] = {
        "INSECURE_PDF_GENERATION": {
            "pattern": r"markdownpdf\s*\(\s*\{.*?html\s*:\s*true",
            "severity": "critical",
            "description": "markdown-pdf configured with html=true, vulnerable to RCE via HTML injection",
            "tags": ["rce", "input-validation"]
        },
        "UNSAFE_USER_INPUT_TO_EXEC": {
            "pattern": r"(generatePDF|spawn|exec|child_process)\s*\(\s*(?:req\.|user|content|input)",
            "severity": "critical",
            "description": "Unsanitized user input passed to code execution function",
            "tags": ["rce", "input-validation", "command-injection"]
        },
        "DIRECT_HTML_RENDERING": {
            "pattern": r'res\.send\s*\(\s*(?:document\.|user\.|\w+\.content)',
            "severity": "high",
            "description": "Rendering user-controlled content directly as HTML without proper escaping",
            "tags": ["xss", "input-validation"]
        },
        "WEAK_AUTH_CONTROL": {
            "pattern": r"(verifyPass|access_pass|debug).*?isAuthenticated.*?isAdmin",
            "severity": "high",
            "description": "Weak authentication mechanism with debug endpoints",
            "tags": ["authentication", "weak-crypto"]
        },
        "HARDCODED_SECRETS": {
            "pattern": r"(SECRET|API_KEY|PASSWORD)\s*=\s*['\"][\w\-]{20,}['\"]",
            "severity": "high",
            "description": "Potential hardcoded secrets or sensitive data",
            "tags": ["secrets", "credential-exposure"]
        },
        "UNSAFE_EVAL": {
            "pattern": r"(eval|Function|vm\.runInThisContext)\s*\(",
            "severity": "critical",
            "description": "Use of eval or dynamic code execution",
            "tags": ["rce", "code-injection"]
        },
        "PATH_TRAVERSAL": {
            "pattern": r"fs\.(readFile|writeFile|unlink)\s*\(\s*(?:req\.|user|String\()",
            "severity": "high",
            "description": "File system operations with unsanitized user input - path traversal risk",
            "tags": ["path-traversal", "input-validation"]
        },
    }

    def __init__(self, config_file: Optional[str] = None, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.rules: Dict[str, SastRule] = {}
        
        # Load rules from config file if provided
        if config_file and Path(config_file).exists():
            self._load_from_file(config_file)
        else:
            # Use default rules
            self._load_defaults()

    def _load_defaults(self):
        """Load default rules."""
        for rule_id, rule_data in self.DEFAULT_RULES.items():
            severity = Severity(rule_data["severity"])
            self.rules[rule_id] = SastRule(
                id=rule_id,
                pattern=rule_data["pattern"],
                severity=severity,
                description=rule_data["description"],
                tags=rule_data.get("tags", [])
            )
        self.logger.info(f"Loaded {len(self.rules)} default SAST rules")

    def _load_from_file(self, config_file: str):
        """Load rules from a JSON configuration file."""
        try:
            with open(config_file, "r") as f:
                config = json.load(f)
            
            for rule_id, rule_data in config.get("rules", {}).items():
                severity = Severity(rule_data.get("severity", "medium"))
                self.rules[rule_id] = SastRule(
                    id=rule_id,
                    pattern=rule_data["pattern"],
                    severity=severity,
                    description=rule_data["description"],
                    tags=rule_data.get("tags", [])
                )
            
            self.logger.info(f"Loaded {len(self.rules)} SAST rules from {config_file}")
        except Exception as e:
            self.logger.warning(f"Failed to load rules from {config_file}, using defaults: {e}")
            self._load_defaults()

    def get_rules(self) -> Dict[str, SastRule]:
        """Get all loaded rules."""
        return self.rules


class StaticAnalyzer:
    """Performs static analysis to detect dangerous code patterns."""

    def __init__(self, config_file: Optional[str] = None, logger: Optional[logging.Logger] = None):
        self.logger = logger or logging.getLogger(__name__)
        self.rule_db = RuleDatabase(config_file, logger)

    def analyze_file(self, file_path: str) -> List[CodeVulnerability]:
        """Analyze a single file for security issues."""
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
                            file_path=file_path,
                            line_number=line_num,
                            description=rule.description,
                            code_snippet=line.strip()
                        ))
        except Exception as e:
            self.logger.warning(f"Could not analyze {file_path}: {e}")
        
        return vulnerabilities

    def analyze_project(self, project_path: str | Path) -> List[CodeVulnerability]:
        """Analyze all code files in project."""
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
    def __init__(self, *, max_workers: int = 4, logger: Optional[logging.Logger] = None, sast_config: Optional[str] = None):
        self.max_workers = max_workers
        self.logger = logger or logging.getLogger(__name__)
        self.parser = DependencyParser()
        self.vuln_db = VulnerabilityDatabase()
        self.sast = StaticAnalyzer(config_file=sast_config, logger=self.logger)

    def scan_project(self, project_path: str | Path, project_name: str = "project") -> SCAResult:
        p = Path(project_path)
        result = SCAResult(project_name=project_name)
        files_to_check = [p / 'requirements.txt', p / 'package.json', p / 'pom.xml', p / 'Dockerfile']
        all_deps: List[Dependency] = []

        for fp in files_to_check:
            if not fp.exists():
                continue
            if fp.name == 'requirements.txt':
                raw = self.parser.parse_requirements_txt(str(fp))
                for name, ver, direct in raw:
                    deps = self._analyze_dependency(name, ver, direct, 'pip')
                    if deps:
                        all_deps.append(deps)
            elif fp.name == 'package.json':
                raw = self.parser.parse_package_json(str(fp))
                for name, ver, direct in raw:
                    dep = self._analyze_dependency(name, ver, direct, 'npm')
                    if dep:
                        all_deps.append(dep)
            elif fp.name == 'pom.xml':
                raw = self.parser.parse_pom_xml(str(fp))
                for name, ver, direct in raw:
                    dep = self._analyze_dependency(name, ver, direct, 'maven')
                    if dep:
                        all_deps.append(dep)
            elif fp.name == 'Dockerfile':
                raw = self.parser.parse_dockerfile(str(fp))
                for name, ver, direct in raw:
                    dep = self._analyze_dependency(name, ver, direct, 'docker')
                    if dep:
                        all_deps.append(dep)

        result.dependencies = sorted(all_deps, key=lambda d: d.risk_score, reverse=True)
        result.calculate_stats = result.calculate_stats  # keep method available
        return result

    def _analyze_dependency(self, name: str, version: str, direct: bool, ecosystem: str) -> Optional[Dependency]:
        try:
            vulnerabilities = self.vuln_db.check_vulnerabilities(name, version, ecosystem)
            license_info = LicenseDatabase.get_license('MIT')
            deprecated = False
            return Dependency(
                name=name,
                version=version,
                package_manager=ecosystem,
                license=license_info,
                vulnerabilities=vulnerabilities,
                direct=direct,
                deprecated=deprecated,
            )
        except Exception:
            self.logger.exception("Error analyzing dependency: %s@%s", name, version)
            return None

    def generate_report(self, result: SCAResult, output_format: str = 'json', output_file: Optional[str] = None, code_vulns: Optional[List[CodeVulnerability]] = None) -> str:
        if output_format == 'json':
            report_dict = {
                'project': result.project_name,
                'scan_date': result.scan_date,
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
                ]
            }
            
            # Add code vulnerabilities if provided
            if code_vulns:
                report_dict['code_vulnerabilities'] = [
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
            
            report = json.dumps(report_dict, indent=2)
        elif output_format == 'text':
            lines: List[str] = []
            lines.append(f"Project: {result.project_name}")
            lines.append(f"Scan Date: {result.scan_date}")
            lines.append("")
            lines.append("=== DEPENDENCY VULNERABILITIES ===")
            lines.append("")
            for d in result.dependencies:
                if d.vulnerabilities:
                    lines.append(f"{d.name} @ {d.version} ({d.package_manager}) risk={d.risk_score}")
                    for v in d.vulnerabilities:
                        lines.append(f"  - [{v.severity.value.upper()}] {v.cve_id}: {v.description}")
                        if v.fixed_version:
                            lines.append(f"    Fixed in: {v.fixed_version}")
            
            if code_vulns:
                lines.append("")
                lines.append("=== CODE VULNERABILITIES (SAST) ===")
                lines.append("")
                for v in code_vulns:
                    lines.append(f"[{v.severity.value.upper()}] {v.rule_id}")
                    lines.append(f"  File: {v.file_path}:{v.line_number}")
                    lines.append(f"  Description: {v.description}")
                    lines.append(f"  Code: {v.code_snippet}")
                    lines.append("")
            
            report = "\n".join(lines)
        elif output_format == 'sbom':
            report = json.dumps({
                'sbom': [
                    {'name': d.name, 'version': d.version, 'pm': d.package_manager}
                    for d in result.dependencies
                ]
            }, indent=2)
        else:
            raise ValueError(f"Unsupported format: {output_format}")

        if output_file:
            with open(output_file, 'w', encoding='utf-8') as f:
                f.write(report)
            self.logger.info("Report written to %s", output_file)

        return report

    def generate_remediation_plan(self, result: SCAResult) -> Dict[str, Any]:
        plan = {'critical': [], 'high': [], 'medium': [], 'low': []}
        for d in result.dependencies:
            entry = {'package': f"{d.name}@{d.version}", 'risk_score': d.risk_score, 'actions': []}
            if d.vulnerabilities:
                for v in d.vulnerabilities:
                    if v.fixed_version:
                        entry['actions'].append(f"Upgrade to {v.fixed_version} for {v.cve_id}")
                    else:
                        entry['actions'].append(f"Investigate {v.cve_id}")
            if d.license and d.license.risk == LicenseRisk.HIGH:
                entry['actions'].append(f"Review license {d.license.name}")
            if d.deprecated:
                entry['actions'].append("Replace deprecated package")

            if d.risk_score >= 8.0:
                plan['critical'].append(entry)
            elif d.risk_score >= 6.0:
                plan['high'].append(entry)
            elif d.risk_score >= 3.0:
                plan['medium'].append(entry)
            else:
                plan['low'].append(entry)
        return plan


# --- Simple CLI demo -----------------------------------------------------

if __name__ == '__main__':
    logging.basicConfig(level=logging.INFO)
    analyzer = SoftwareCompositionAnalyzer(max_workers=4)
    project_dir = Path('.')
    
    # Run SCA scan
    res = analyzer.scan_project(project_dir, project_name='DarkRunes')
    
    # Run SAST scan
    code_vulns = analyzer.sast.analyze_project(project_dir)
    
    # Generate combined report
    print(analyzer.generate_report(res, output_format='text', code_vulns=code_vulns))
    
    # Write JSON report with both findings
    analyzer.generate_report(res, output_format='json', output_file='sca_report.json', code_vulns=code_vulns)
    
    # Generate remediation plan
    plan = analyzer.generate_remediation_plan(res)
    
    # Add code vulnerabilities to remediation plan
    if code_vulns:
        plan['code_vulnerabilities'] = [
            {
                'file': v.file_path,
                'line': v.line_number,
                'rule': v.rule_id,
                'severity': v.severity.value,
                'description': v.description,
                'action': f"Fix {v.rule_id} in {v.file_path}:{v.line_number}"
            }
            for v in code_vulns
        ]
    
    with open('remediation_plan.json', 'w', encoding='utf-8') as fh:
        json.dump(plan, fh, indent=2)
    
    print('\nReports generated: sca_report.json, remediation_plan.json')
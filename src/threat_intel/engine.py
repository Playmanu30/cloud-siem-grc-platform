"""
Threat Intelligence Module
Enriches IOCs using VirusTotal, Shodan, and AbuseIPDB
"""

import hashlib
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
import requests
from ..utils.logging import get_logger

logger = get_logger(__name__)


class ThreatIntelligenceEngine:
    """Enriches Indicators of Compromise (IOCs) using external threat intelligence feeds"""

    def __init__(
        self,
        virustotal_api_key: Optional[str] = None,
        shodan_api_key: Optional[str] = None,
        abuseipdb_api_key: Optional[str] = None,
    ):
        self.vt_api_key = virustotal_api_key
        self.shodan_api_key = shodan_api_key
        self.abuseipdb_api_key = abuseipdb_api_key

        # Rate limiting
        self._last_vt_call = 0
        self._vt_rate_limit = 15  # seconds between VT calls (free tier: 4/min)

        # IOC cache to avoid redundant lookups
        self._cache: Dict[str, Dict[str, Any]] = {}
        self._cache_ttl = 86400  # 24 hours in seconds

        logger.info(
            "Threat intelligence engine initialized",
            virustotal=bool(virustotal_api_key),
            shodan=bool(shodan_api_key),
            abuseipdb=bool(abuseipdb_api_key),
        )

    # ── VirusTotal ──────────────────────────────────────────────

    def _vt_rate_wait(self) -> None:
        """Enforce VirusTotal rate limit"""
        elapsed = time.time() - self._last_vt_call
        if elapsed < self._vt_rate_limit:
            time.sleep(self._vt_rate_limit - elapsed)
        self._last_vt_call = time.time()

    def lookup_ip_virustotal(self, ip: str) -> Dict[str, Any]:
        """
        Look up an IP in VirusTotal

        Args:
            ip: IPv4 or IPv6 address

        Returns:
            VirusTotal analysis results
        """
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not configured"}

        cache_key = f"vt:ip:{ip}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        self._vt_rate_wait()

        try:
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/ip_addresses/{ip}",
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})

            result = {
                "ip": ip,
                "source": "VirusTotal",
                "malicious_count": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious_count": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "harmless_count": attributes.get("last_analysis_stats", {}).get("harmless", 0),
                "undetected_count": attributes.get("last_analysis_stats", {}).get("undetected", 0),
                "reputation": attributes.get("reputation", 0),
                "country": attributes.get("country", "Unknown"),
                "as_owner": attributes.get("as_owner", "Unknown"),
                "network": attributes.get("network", "Unknown"),
                "last_analysis_date": attributes.get("last_analysis_date"),
                "risk_score": self._calculate_vt_risk_score(attributes),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            self._set_cached(cache_key, result)
            logger.info("VirusTotal IP lookup complete", ip=ip, malicious=result["malicious_count"])
            return result

        except requests.exceptions.HTTPError as e:
            logger.error("VirusTotal API error", ip=ip, status=e.response.status_code)
            return {"error": f"API error: {e.response.status_code}", "ip": ip}
        except Exception as e:
            logger.error("VirusTotal lookup failed", ip=ip, error=str(e))
            return {"error": str(e), "ip": ip}

    def lookup_hash_virustotal(self, file_hash: str) -> Dict[str, Any]:
        """
        Look up a file hash in VirusTotal

        Args:
            file_hash: MD5, SHA1, or SHA256 hash

        Returns:
            VirusTotal analysis results
        """
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not configured"}

        cache_key = f"vt:hash:{file_hash}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        self._vt_rate_wait()

        try:
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/files/{file_hash}",
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})
            stats = attributes.get("last_analysis_stats", {})

            result = {
                "hash": file_hash,
                "source": "VirusTotal",
                "file_name": attributes.get("meaningful_name", "Unknown"),
                "file_type": attributes.get("type_description", "Unknown"),
                "file_size": attributes.get("size", 0),
                "malicious_count": stats.get("malicious", 0),
                "suspicious_count": stats.get("suspicious", 0),
                "undetected_count": stats.get("undetected", 0),
                "total_engines": sum(stats.values()),
                "tags": attributes.get("tags", []),
                "first_seen": attributes.get("first_submission_date"),
                "last_seen": attributes.get("last_analysis_date"),
                "risk_score": self._calculate_vt_risk_score(attributes),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            self._set_cached(cache_key, result)
            logger.info("VirusTotal hash lookup complete", hash=file_hash, malicious=result["malicious_count"])
            return result

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return {"hash": file_hash, "source": "VirusTotal", "found": False}
            logger.error("VirusTotal API error", hash=file_hash, status=e.response.status_code)
            return {"error": f"API error: {e.response.status_code}", "hash": file_hash}
        except Exception as e:
            logger.error("VirusTotal hash lookup failed", hash=file_hash, error=str(e))
            return {"error": str(e), "hash": file_hash}

    def lookup_domain_virustotal(self, domain: str) -> Dict[str, Any]:
        """Look up a domain in VirusTotal"""
        if not self.vt_api_key:
            return {"error": "VirusTotal API key not configured"}

        cache_key = f"vt:domain:{domain}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        self._vt_rate_wait()

        try:
            headers = {"x-apikey": self.vt_api_key}
            response = requests.get(
                f"https://www.virustotal.com/api/v3/domains/{domain}",
                headers=headers,
                timeout=30,
            )
            response.raise_for_status()
            data = response.json().get("data", {})
            attributes = data.get("attributes", {})

            result = {
                "domain": domain,
                "source": "VirusTotal",
                "malicious_count": attributes.get("last_analysis_stats", {}).get("malicious", 0),
                "suspicious_count": attributes.get("last_analysis_stats", {}).get("suspicious", 0),
                "reputation": attributes.get("reputation", 0),
                "registrar": attributes.get("registrar", "Unknown"),
                "creation_date": attributes.get("creation_date"),
                "categories": attributes.get("categories", {}),
                "risk_score": self._calculate_vt_risk_score(attributes),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            self._set_cached(cache_key, result)
            logger.info("VirusTotal domain lookup complete", domain=domain)
            return result

        except Exception as e:
            logger.error("VirusTotal domain lookup failed", domain=domain, error=str(e))
            return {"error": str(e), "domain": domain}

    # ── Shodan ──────────────────────────────────────────────────

    def lookup_ip_shodan(self, ip: str) -> Dict[str, Any]:
        """
        Look up an IP in Shodan for exposed services and vulnerabilities

        Args:
            ip: IPv4 address

        Returns:
            Shodan host information
        """
        if not self.shodan_api_key:
            return {"error": "Shodan API key not configured"}

        cache_key = f"shodan:ip:{ip}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        try:
            response = requests.get(
                f"https://api.shodan.io/shodan/host/{ip}",
                params={"key": self.shodan_api_key},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json()

            result = {
                "ip": ip,
                "source": "Shodan",
                "os": data.get("os"),
                "organization": data.get("org", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "country": data.get("country_name", "Unknown"),
                "city": data.get("city", "Unknown"),
                "open_ports": data.get("ports", []),
                "vulns": data.get("vulns", []),
                "hostnames": data.get("hostnames", []),
                "domains": data.get("domains", []),
                "services": [
                    {
                        "port": service.get("port"),
                        "transport": service.get("transport"),
                        "product": service.get("product"),
                        "version": service.get("version"),
                        "cpe": service.get("cpe", []),
                    }
                    for service in data.get("data", [])
                ],
                "last_update": data.get("last_update"),
                "risk_score": self._calculate_shodan_risk_score(data),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            self._set_cached(cache_key, result)
            logger.info(
                "Shodan IP lookup complete",
                ip=ip,
                open_ports=len(result["open_ports"]),
                vulns=len(result["vulns"]),
            )
            return result

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 404:
                return {"ip": ip, "source": "Shodan", "found": False}
            logger.error("Shodan API error", ip=ip, status=e.response.status_code)
            return {"error": f"API error: {e.response.status_code}", "ip": ip}
        except Exception as e:
            logger.error("Shodan lookup failed", ip=ip, error=str(e))
            return {"error": str(e), "ip": ip}

    # ── AbuseIPDB ───────────────────────────────────────────────

    def lookup_ip_abuseipdb(self, ip: str) -> Dict[str, Any]:
        """
        Look up an IP in AbuseIPDB for abuse reports

        Args:
            ip: IPv4 or IPv6 address

        Returns:
            AbuseIPDB report
        """
        if not self.abuseipdb_api_key:
            return {"error": "AbuseIPDB API key not configured"}

        cache_key = f"abuseipdb:ip:{ip}"
        cached = self._get_cached(cache_key)
        if cached:
            return cached

        try:
            headers = {"Key": self.abuseipdb_api_key, "Accept": "application/json"}
            response = requests.get(
                "https://api.abuseipdb.com/api/v2/check",
                headers=headers,
                params={"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""},
                timeout=30,
            )
            response.raise_for_status()
            data = response.json().get("data", {})

            result = {
                "ip": ip,
                "source": "AbuseIPDB",
                "abuse_confidence_score": data.get("abuseConfidenceScore", 0),
                "total_reports": data.get("totalReports", 0),
                "num_distinct_users": data.get("numDistinctUsers", 0),
                "country_code": data.get("countryCode", "Unknown"),
                "isp": data.get("isp", "Unknown"),
                "domain": data.get("domain", "Unknown"),
                "is_whitelisted": data.get("isWhitelisted", False),
                "is_tor": data.get("isTor", False),
                "usage_type": data.get("usageType", "Unknown"),
                "last_reported_at": data.get("lastReportedAt"),
                "categories": data.get("reports", [{}])[0].get("categories", []) if data.get("reports") else [],
                "risk_score": min(data.get("abuseConfidenceScore", 0), 100),
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }

            self._set_cached(cache_key, result)
            logger.info(
                "AbuseIPDB lookup complete",
                ip=ip,
                abuse_score=result["abuse_confidence_score"],
            )
            return result

        except Exception as e:
            logger.error("AbuseIPDB lookup failed", ip=ip, error=str(e))
            return {"error": str(e), "ip": ip}

    # ── Multi-Source Enrichment ─────────────────────────────────

    def enrich_ip(self, ip: str) -> Dict[str, Any]:
        """
        Enrich an IP address using ALL available threat intelligence sources

        Args:
            ip: IPv4 or IPv6 address

        Returns:
            Combined results from all sources with aggregate risk score
        """
        results = {"ip": ip, "sources": {}, "timestamp": datetime.now(timezone.utc).isoformat()}
        risk_scores = []

        # VirusTotal
        if self.vt_api_key:
            vt_result = self.lookup_ip_virustotal(ip)
            results["sources"]["virustotal"] = vt_result
            if "risk_score" in vt_result:
                risk_scores.append(vt_result["risk_score"])

        # Shodan
        if self.shodan_api_key:
            shodan_result = self.lookup_ip_shodan(ip)
            results["sources"]["shodan"] = shodan_result
            if "risk_score" in shodan_result:
                risk_scores.append(shodan_result["risk_score"])

        # AbuseIPDB
        if self.abuseipdb_api_key:
            abuse_result = self.lookup_ip_abuseipdb(ip)
            results["sources"]["abuseipdb"] = abuse_result
            if "risk_score" in abuse_result:
                risk_scores.append(abuse_result["risk_score"])

        # Calculate aggregate risk score
        if risk_scores:
            results["aggregate_risk_score"] = round(sum(risk_scores) / len(risk_scores), 1)
            results["max_risk_score"] = max(risk_scores)
            results["risk_level"] = self._risk_level(results["max_risk_score"])
        else:
            results["aggregate_risk_score"] = 0
            results["risk_level"] = "unknown"

        logger.info(
            "IP enrichment complete",
            ip=ip,
            sources=len(results["sources"]),
            risk_level=results["risk_level"],
        )
        return results

    def enrich_iocs(self, iocs: List[Dict[str, str]]) -> List[Dict[str, Any]]:
        """
        Batch enrich multiple IOCs

        Args:
            iocs: List of {"type": "ip|hash|domain", "value": "..."}

        Returns:
            List of enrichment results
        """
        results = []

        for ioc in iocs:
            ioc_type = ioc.get("type", "").lower()
            ioc_value = ioc.get("value", "")

            if not ioc_value:
                continue

            if ioc_type == "ip":
                result = self.enrich_ip(ioc_value)
            elif ioc_type == "hash":
                result = self.lookup_hash_virustotal(ioc_value)
            elif ioc_type == "domain":
                result = self.lookup_domain_virustotal(ioc_value)
            else:
                result = {"error": f"Unsupported IOC type: {ioc_type}", "value": ioc_value}

            results.append(result)

        logger.info("Batch IOC enrichment complete", total=len(iocs), processed=len(results))
        return results

    # ── Risk Scoring ────────────────────────────────────────────

    def _calculate_vt_risk_score(self, attributes: Dict[str, Any]) -> int:
        """Calculate risk score from VirusTotal attributes (0-100)"""
        stats = attributes.get("last_analysis_stats", {})
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1

        detection_ratio = (malicious + suspicious * 0.5) / total
        reputation = attributes.get("reputation", 0)
        reputation_factor = max(0, min(1, (50 - reputation) / 100)) if reputation < 0 else 0

        score = min(100, int(detection_ratio * 80 + reputation_factor * 20))
        return score

    def _calculate_shodan_risk_score(self, data: Dict[str, Any]) -> int:
        """Calculate risk score from Shodan data (0-100)"""
        score = 0

        # Open ports risk
        ports = data.get("ports", [])
        risky_ports = {21, 23, 445, 1433, 3306, 3389, 5900, 6379, 27017}
        for port in ports:
            if port in risky_ports:
                score += 10
            else:
                score += 2

        # Vulnerabilities
        vulns = data.get("vulns", [])
        score += len(vulns) * 15

        return min(100, score)

    def _risk_level(self, score: int) -> str:
        """Convert numeric risk score to risk level label"""
        if score >= 80:
            return "critical"
        elif score >= 60:
            return "high"
        elif score >= 40:
            return "medium"
        elif score >= 20:
            return "low"
        else:
            return "info"

    # ── Caching ─────────────────────────────────────────────────

    def _get_cached(self, key: str) -> Optional[Dict[str, Any]]:
        """Get a cached result if still valid"""
        if key in self._cache:
            entry = self._cache[key]
            age = time.time() - entry.get("_cached_at", 0)
            if age < self._cache_ttl:
                logger.debug("Cache hit", key=key)
                return entry.get("data")
        return None

    def _set_cached(self, key: str, data: Dict[str, Any]) -> None:
        """Cache a result"""
        self._cache[key] = {"data": data, "_cached_at": time.time()}

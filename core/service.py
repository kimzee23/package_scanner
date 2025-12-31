from typing import Dict


class RiskCalculator:
    """Enhanced risk calculation service"""

    def calculate_package_risk(self, package_data: Dict) -> float:
        """Calculate comprehensive risk score (0-100)"""

        factors = {
            'security': self._calculate_security_score(package_data),
            'maintenance': self._calculate_maintenance_score(package_data),
            'popularity': self._calculate_popularity_score(package_data),
            'license': self._calculate_license_score(package_data),
        }

        weights = {
            'security': 0.4,
            'maintenance': 0.3,
            'popularity': 0.2,
            'license': 0.1,
        }

        # Weighted average
        total_score = sum(factors[key] * weights[key] for key in factors)
        return min(total_score, 100.0)

    def _calculate_security_score(self, package_data: Dict) -> float:
        """Calculate security risk (0-100) - higher = more risky"""
        score = 0

        if package_data.get('has_vulnerabilities', False):
            score += 40

        # Check for suspicious patterns in package name
        name = str(package_data.get('name', '')).lower()
        suspicious_keywords = ['test', 'example', 'demo', 'fake', 'malicious']
        if any(keyword in name for keyword in suspicious_keywords):
            score += 20

        # Check author reputation
        author = str(package_data.get('author', '')).lower()
        if not author or author in ['unknown', 'anonymous', '']:
            score += 10

        return min(score, 100)

    def _calculate_maintenance_score(self, package_data: Dict) -> float:
        """Calculate maintenance risk (0-100) - higher = more risky"""
        score = 0

        if package_data.get('is_deprecated', False):
            score += 50

        if package_data.get('is_unmaintained', False):
            score += 30

        # Check last update (simplified logic)
        last_updated = str(package_data.get('last_updated', ''))

        # Very basic date checking - enhance this later
        if '2020' in last_updated or '2019' in last_updated:
            score += 20
        elif '2021' in last_updated:
            score += 15
        elif '2022' in last_updated:
            score += 10
        elif '2023' in last_updated:
            score += 5

        return min(score, 100)

    def _calculate_popularity_score(self, package_data: Dict) -> float:
        """
        Calculate popularity-based risk score.

        Lower adoption implies higher risk.
        Score range: 10 (very low risk) → 80 (high risk)
        """

        downloads = self._extract_download_count(package_data)

        # Thresholds ordered by ascending popularity
        risk_bands = (
            (100, 80.0),
            (1_000, 60.0),
            (10_000, 40.0),
            (100_000, 20.0),
        )

        for threshold, score in risk_bands:
            if downloads < threshold:
                return score

        return 10.0  # Very low risk for widely adopted packages

    def _extract_download_count(self, package_data: Dict) -> int:
        """
        Normalize download count from various provider formats.
        """
        downloads = package_data.get("downloads", 0)

        if isinstance(downloads, dict):
            return int(downloads.get("downloads", 0))

        if isinstance(downloads, (int, float)):
            return int(downloads)

        return 0

    def _calculate_license_score(self, package_data: Dict) -> float:
        """Calculate license risk (higher = more risky)"""
        license_text = str(package_data.get('license', '')).lower()

        # Safe licenses (low risk)
        safe_licenses = ['mit', 'apache', 'bsd', 'isc', 'unlicense']
        # Risky licenses (medium-high risk)
        risky_licenses = ['gpl', 'agpl', 'lgpl']
        # Very risky (proprietary or unknown)

        if any(license in license_text for license in safe_licenses):
            return 10  # Low risk

        if any(license in license_text for license in risky_licenses):
            return 50  # Medium risk

        if not license_text or 'unknown' in license_text or 'proprietary' in license_text:
            return 70  # High risk (unknown/proprietary license)

        return 30  # Medium-low risk for other licenses
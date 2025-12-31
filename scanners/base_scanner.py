from abc import ABC, abstractmethod
import requests
from typing import Dict, List, Optional


class BasePackageScanner(ABC):
    """Abstract base class for all package scanners"""

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'PackageScanner/1.0'
        })

    @abstractmethod
    def get_package_info(self, package_name: str) -> Dict:
        """Get package information from registry"""
        pass

    @abstractmethod
    def parse_dependencies(self, file_content: str) -> List[Dict]:
        """Parse dependencies from package file"""
        pass

    def calculate_risk_score(self, package_data: Dict) -> float:
        """Calculate risk score (0-100) for a package"""
        score = 50.0  # Default

        # Simple scoring logic (expand later)
        if package_data.get('has_vulnerabilities'):
            score += 30
        if package_data.get('is_deprecated'):
            score += 20
        if package_data.get('is_unmaintained'):
            score += 25

        return min(score, 100.0)
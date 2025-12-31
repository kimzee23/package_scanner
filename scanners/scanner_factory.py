from .npm_scanner import NPMPackageScanner
from .pypi_scanner import PyPIPackageScanner


class ScannerFactory:
    """Factory to create appropriate scanner based on ecosystem"""

    @staticmethod
    def get_scanner(ecosystem: str):
        """Get scanner instance for the given ecosystem"""
        scanners = {
            'npm': NPMPackageScanner,
            'pypi': PyPIPackageScanner,
            # 'maven': MavenPackageScanner,
            # 'go': GoPackageScanner,
        }

        scanner_class = scanners.get(ecosystem.lower())
        if scanner_class:
            return scanner_class()
        else:
            raise ValueError(f"Unsupported ecosystem: {ecosystem}")

    @staticmethod
    def detect_ecosystem(filename: str) -> str:
        """Detect ecosystem from filename"""
        filename_lower = filename.lower()

        if filename_lower == 'package.json':
            return 'npm'
        elif filename_lower == 'requirements.txt':
            return 'pypi'
        elif filename_lower == 'pom.xml':
            return 'maven'
        elif filename_lower == 'go.mod':
            return 'go'
        elif filename_lower.endswith('.json'):
            return 'npm'  # Default assumption
        else:
            return 'unknown'
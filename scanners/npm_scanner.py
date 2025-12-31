import json
import requests
from typing import Dict, List, Optional
from .base_scanner import BasePackageScanner


class NPMPackageScanner(BasePackageScanner):
    """Scanner for NPM packages"""

    def __init__(self):
        super().__init__()
        self.registry_url = "https://registry.npmjs.org"

    def get_package_info(self, package_name: str) -> Dict:
        """Get package info from NPM registry"""
        try:
            response = self.session.get(f"{self.registry_url}/{package_name}")
            response.raise_for_status()
            data = response.json()

            latest_version = data.get('dist-tags', {}).get('latest', '')
            latest_data = data.get('versions', {}).get(latest_version, {})

            return {
                'name': package_name,
                'version': latest_version,
                'description': data.get('description', ''),
                'author': self._extract_author(data.get('author', {})),
                'last_updated': data.get('time', {}).get(latest_version, ''),
                'license': latest_data.get('license', ''),
                'dependencies': latest_data.get('dependencies', {}),
                'has_vulnerabilities': self._check_vulnerabilities(package_name),
                'is_deprecated': 'deprecated' in data,
                'downloads': self._get_download_stats(package_name),
            }
        except requests.RequestException as e:
            return {
                'name': package_name,
                'error': str(e),
                'has_vulnerabilities': False,
                'is_deprecated': False,
            }

    def parse_dependencies(self, file_content: str) -> List[Dict]:
        """Parse dependencies from package.json"""
        try:
            package_json = json.loads(file_content)
            dependencies = []

            # Get dependencies
            deps = package_json.get('dependencies', {})
            dev_deps = package_json.get('devDependencies', {})

            for name, version in {**deps, **dev_deps}.items():
                dependencies.append({
                    'name': name,
                    'version': version,
                    'type': 'dependency' if name in deps else 'devDependency'
                })

            return dependencies
        except json.JSONDecodeError:
            return []

    def _extract_author(self, author_data) -> str:
        """Extract author name from author data"""
        if isinstance(author_data, str):
            return author_data
        elif isinstance(author_data, dict):
            return author_data.get('name', 'Unknown')
        return 'Unknown'

    def _check_vulnerabilities(self, package_name: str) -> bool:
        """Check if package has known vulnerabilities"""
        # TODO: Integrate with OSV database or npm audit
        # For now, return False
        return False

    def _get_download_stats(self, package_name: str) -> Dict:
        """Get download statistics"""
        try:
            response = self.session.get(
                f"https://api.npmjs.org/downloads/point/last-week/{package_name}"
            )
            if response.status_code == 200:
                return response.json()
        except:
            pass
        return {'downloads': 0}
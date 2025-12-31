from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework.permissions import AllowAny
from django.utils import timezone
import json

from core.models import ScanRequest, ScanResult, Package, PackageScanResult
from core.service import RiskCalculator
from scanners import ScannerFactory



class ScanFileView(APIView):
    """API endpoint to scan a package file"""
    permission_classes = [AllowAny]

    def post(self, request):
        try:
            # Get data from request
            file_content = request.data.get('content', '')
            filename = request.data.get('filename', 'package.json')
            ecosystem = request.data.get('ecosystem')

            if not ecosystem:
                ecosystem = ScannerFactory.detect_ecosystem(filename)

            if not file_content:
                return Response(
                    {'error': 'No file content provided'},
                    status=status.HTTP_400_BAD_REQUEST
                )

            # Create scan request record
            scan_request = ScanRequest.objects.create(
                user=request.user if request.user.is_authenticated else None,
                source='web' if request.user.is_authenticated else 'cli',
                target=filename,
                status='processing'
            )

            # Get appropriate scanner
            scanner = ScannerFactory.get_scanner(ecosystem)
            dependencies = scanner.parse_dependencies(file_content)

            # Scan each package
            results = []
            risk_calculator = RiskCalculator()

            for dep in dependencies[:10]:  # Limit for testing
                package_info = scanner.get_package_info(dep['name'], dep.get('version_constraint'))
                risk_score = risk_calculator.calculate_package_risk(package_info)

                # Save or get package from database
                package, _ = Package.objects.get_or_create(
                    name=dep['name'],
                    ecosystem=ecosystem,
                    defaults={
                        'version': package_info.get('version'),
                        'description': package_info.get('description', ''),
                        'author': package_info.get('author', ''),
                        'last_updated': timezone.now(),  # Placeholder
                    }
                )

                results.append({
                    'package': dep['name'],
                    'version': package_info.get('version', 'unknown'),
                    'version_constraint': dep.get('version_constraint', ''),
                    'type': dep.get('type', 'dependency'),
                    'risk_score': float(risk_score),
                    'has_vulnerabilities': package_info.get('has_vulnerabilities', False),
                    'is_deprecated': package_info.get('is_deprecated', False),
                    'details': {
                        k: v for k, v in package_info.items()
                        if k not in ['error'] and not isinstance(v, (dict, list))
                    }
                })

            # Calculate overall risk
            overall_risk = sum(r['risk_score'] for r in results) / len(results) if results else 0

            # Create scan result
            scan_result = ScanResult.objects.create(
                scan_request=scan_request,
                overall_risk_score=overall_risk,
                report_path=f"/api/reports/{scan_request.id}.json"
            )

            # Save individual package results
            for result in results:
                package = Package.objects.get(name=result['package'], ecosystem=ecosystem)
                PackageScanResult.objects.create(
                    scan_result=scan_result,
                    package=package,
                    risk_score=result['risk_score'],
                    vulnerabilities_found=1 if result['has_vulnerabilities'] else 0,
                    is_deprecated=result['is_deprecated'],
                    raw_data=result['details']
                )

            # Update scan request status
            scan_request.status = 'completed'
            scan_request.completed_at = timezone.now()
            scan_request.save()

            return Response({
                'status': 'success',
                'scan_id': str(scan_request.id),
                'ecosystem': ecosystem,
                'packages_scanned': len(results),
                'overall_risk_score': float(overall_risk),
                'results': results,
                'summary': self._generate_summary(results),
                'report_url': f"/api/reports/{scan_request.id}"
            })

        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error': f'Internal server error: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

    def _generate_summary(self, results):
        """Generate a simple summary"""
        total = len(results)
        risky = sum(1 for r in results if r['risk_score'] > 70)
        vulnerabilities = sum(1 for r in results if r['has_vulnerabilities'])
        deprecated = sum(1 for r in results if r['is_deprecated'])

        return {
            'total_packages': total,
            'risky_packages': risky,
            'packages_with_vulnerabilities': vulnerabilities,
            'deprecated_packages': deprecated,
        }


class CheckPackageView(APIView):
    """Check a single package"""
    permission_classes = [AllowAny]

    def get(self, request):
        package_name = request.GET.get('package')
        ecosystem = request.GET.get('ecosystem', 'npm')
        version = request.GET.get('version')

        if not package_name:
            return Response(
                {'error': 'Package name is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            scanner = ScannerFactory.get_scanner(ecosystem)
            package_info = scanner.get_package_info(package_name, version)

            risk_calculator = RiskCalculator()
            risk_score = risk_calculator.calculate_package_risk(package_info)

            response_data = {
                'package': package_name,
                'ecosystem': ecosystem,
                'risk_score': float(risk_score),
                'details': {
                    k: v for k, v in package_info.items()
                    if k not in ['error'] and not isinstance(v, (dict, list))
                }
            }

            # Add risk level
            if risk_score >= 80:
                response_data['risk_level'] = 'CRITICAL'
            elif risk_score >= 60:
                response_data['risk_level'] = 'HIGH'
            elif risk_score >= 40:
                response_data['risk_level'] = 'MEDIUM'
            else:
                response_data['risk_level'] = 'LOW'

            return Response(response_data)

        except ValueError as e:
            return Response(
                {'error': str(e)},
                status=status.HTTP_400_BAD_REQUEST
            )
        except Exception as e:
            return Response(
                {'error': f'Error checking package: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )


class ScanReportView(APIView):
    """Get scan report by ID"""
    permission_classes = [AllowAny]

    def get(self, request, scan_id):
        try:
            scan_result = ScanResult.objects.get(scan_request__id=scan_id)
            package_results = PackageScanResult.objects.filter(
                scan_result=scan_result
            ).select_related('package')

            results = []
            for pr in package_results:
                results.append({
                    'package': pr.package.name,
                    'ecosystem': pr.package.ecosystem,
                    'risk_score': float(pr.risk_score),
                    'vulnerabilities_found': pr.vulnerabilities_found,
                    'is_deprecated': pr.is_deprecated,
                    'is_unmaintained': pr.is_unmaintained,
                })

            return Response({
                'scan_id': scan_id,
                'overall_risk_score': float(scan_result.overall_risk_score),
                'created_at': scan_result.created_at,
                'results': results,
                'total_packages': len(results)
            })

        except ScanResult.DoesNotExist:
            return Response(
                {'error': 'Scan result not found'},
                status=status.HTTP_404_NOT_FOUND
            )
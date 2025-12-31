from django.urls import path
from . import views

urlpatterns = [
    path('scan/file/', views.ScanFileView.as_view(), name='scan-file'),
    path('check/package/', views.CheckPackageView.as_view(), name='check-package'),
    path('reports/<uuid:scan_id>/', views.ScanReportView.as_view(), name='scan-report'),
]
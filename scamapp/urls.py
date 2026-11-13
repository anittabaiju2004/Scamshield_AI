from unicodedata import name
from django.urls import path

from . import views

urlpatterns = [
    # Public
    path('', views.home, name='home'),
    path('register/', views.register, name='register'),
    path('login/', views.login, name='login'),
    path('logout/', views.user_logout, name='logout'),

    # Dashboards
    path('dashboard/', views.user_dashboard, name='user_dashboard'),
    path('admin-panel/', views.admin_dashboard, name='admin_dashboard'),

    #User management
    path('users/', views.user_management, name='user_management'),
    path('users/toggle_user_status/<int:user_id>/', views.toggle_user_status, name='toggle_user_status'),


    #Message Scanner
    path('message-scanner/',views.message_scanner,name='message_scanner'),
    path('scan-history/',views.scan_history,name='scan_history'),
    path('scan-detail/<int:scan_id>/',views.scan_detail,name='scan_detail'),

    #Url Scanner
    path('url-scanner/',views.url_scanner,name='url_scanner'),
    path('url-scan-history/',views.url_scan_history,name='url_scan_history'),
    path('url-scan-detail/<int:scan_id>/',views.url_scan_detail,name='url_scan_detail'),

    #Profile Management
    path('profile/', views.user_profile, name='user_profile'),



    #Admin view message scans
    path('admin_message-scans/',views.admin_message_scans,name='admin_message_scans'),

    #Admin view detected scams
    path('admin_detected-scams/',views.admin_detected_scams,name='admin_detected_scams'),

    #Admin view risk analysis
    path('admin_risk-analysis/',views.admin_risk_analysis,name='admin_risk_analysis'),
]
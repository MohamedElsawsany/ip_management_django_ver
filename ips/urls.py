# ips/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path('login/', views.login_view, name='login'),
    path('logout/', views.logout_view, name='logout'),
    
    # Main views
    path('', views.index, name='index'),
    path('bulk-insert/', views.bulk_insert, name='bulk_insert'),
    
    # IP CRUD operations
    path('ip/<int:ip_id>/edit/', views.edit_ip, name='edit_ip'),
    
    # Ping feature
    path('ip/<int:ip_id>/ping/', views.ping_ip, name='ping_ip'),
    
    # API endpoints
    path('api/branches/', views.get_branches, name='api_branches'),
    path('api/networks/', views.get_networks, name='api_networks'),
    path('api/device-types/', views.get_device_types, name='api_device_types'),
    path('api/subnets/', views.get_subnets, name='api_subnets'),
    path('api/ips/datatable/', views.get_ips_datatable, name='api_ips_datatable'),
]
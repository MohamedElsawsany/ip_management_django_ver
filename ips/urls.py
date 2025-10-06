# ips/urls.py
from django.urls import path
from . import views

urlpatterns = [
    # Authentication
    path("login/", views.login_view, name="login"),
    path("logout/", views.logout_view, name="logout"),
    # Main views
    path("", views.index, name="index"),
    path("bulk-insert/", views.bulk_insert, name="bulk_insert"),
    # Branch CRUD (Admin only)
    path("branches/", views.branches_list, name="branches_list"),
    path("branches/create/", views.create_branch, name="create_branch"),
    path("branches/<int:branch_id>/edit/", views.edit_branch, name="edit_branch"),
    path("branches/<int:branch_id>/delete/", views.delete_branch, name="delete_branch"),
    # IP CRUD operations
    path("ip/<int:ip_id>/edit/", views.edit_ip, name="edit_ip"),
    # Ping feature
    path("ip/<int:ip_id>/ping/", views.ping_ip, name="ping_ip"),
    # API endpoints
    path("api/branches/", views.get_branches, name="api_branches"),
    path("api/networks/", views.get_networks, name="api_networks"),
    path("api/device-types/", views.get_device_types, name="api_device_types"),
    path("api/subnets/", views.get_subnets, name="api_subnets"),
    path("api/ips/datatable/", views.get_ips_datatable, name="api_ips_datatable"),
    path("api/ips/bulk-delete/", views.bulk_delete_ips, name="api_bulk_delete_ips"),  # NEW
    # User Management (Admin only)
    path("users/", views.users_list, name="users_list"),
    path("users/create/", views.create_user, name="create_user"),
    path("users/<int:user_id>/edit/", views.edit_user, name="edit_user"),
    path("users/<int:user_id>/delete/", views.delete_user, name="delete_user"),
    path(
        "users/<int:user_id>/change-password/",
        views.change_user_password,
        name="change_user_password",
    ),
    path(
        "users/<int:user_id>/toggle-status/",
        views.toggle_user_status,
        name="toggle_user_status",
    ),
]
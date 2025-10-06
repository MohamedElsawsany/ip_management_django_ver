# ips/views.py
from urllib import request
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.decorators import login_required
from django.contrib.auth import login, logout, authenticate
from django.contrib import messages
from django.http import JsonResponse
from django.db.models import Q, Count
from django.views.decorators.http import require_http_methods
from django.core.paginator import Paginator
from django.db import transaction, IntegrityError
from django.core.validators import validate_ipv4_address
from django.core.exceptions import ValidationError
from django.contrib.auth.models import User
from .forms import UserForm, UserEditForm, PasswordChangeForm
import json
import logging
import subprocess
import platform

from .models import Branch, DeviceType, Subnet, IP, UserProfile
from .forms import IPForm, BulkIPForm, BranchForm

logger = logging.getLogger(__name__)


def is_admin(user):
    """Check if user has admin privileges"""
    if user.is_superuser:
        return True
    if hasattr(user, "profile"):
        return user.profile.is_admin
    return False


def get_user_branch(user):
    """Get user's assigned branch"""
    if hasattr(user, "profile"):
        return user.profile.branch
    return None


def login_view(request):
    """User login view with proper error handling"""
    if request.user.is_authenticated:
        return redirect("index")

    if request.method == "POST":
        username = request.POST.get("username", "").strip()
        password = request.POST.get("password", "")

        if not username or not password:
            messages.error(request, "Please provide both username and password")
            return render(request, "ips/login.html")

        user = authenticate(request, username=username, password=password)

        if user is not None:
            login(request, user)
            next_url = request.GET.get("next", "index")
            if not next_url.startswith("/"):
                next_url = "index"
            return redirect(next_url)
        else:
            messages.error(request, "Invalid username or password")

    return render(request, "ips/login.html")


@login_required
def logout_view(request):
    """User logout view"""
    logout(request)
    messages.success(request, "You have been logged out successfully")
    return redirect("login")


@login_required
def index(request):
    """Main dashboard view with permission handling"""
    try:
        user_is_admin = is_admin(request.user)
        user_branch = get_user_branch(request.user)

        # Get all branches for display
        branches = Branch.objects.all().order_by("name")

        context = {
            "branches": branches,
            "is_admin": user_is_admin,
            "user_branch": user_branch,
        }

        return render(request, "ips/index.html", context)

    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}", exc_info=True)
        messages.error(request, f"Error loading dashboard: {str(e)}")

        context = {
            "branches": [],
            "is_admin": False,
            "user_branch": None,
        }
        return render(request, "ips/index.html", context)


# ==================== BRANCH CRUD OPERATIONS ====================


@login_required
def branches_list(request):
    """List all branches - Admin only"""
    if not is_admin(request.user):
        messages.error(request, "You do not have permission to manage branches")
        return redirect("index")

    branches = Branch.objects.all().order_by("name")

    context = {
        "branches": branches,
        "is_admin": True,
    }

    return render(request, "ips/branches_list.html", context)


@login_required
@require_http_methods(["GET", "POST"])
def create_branch(request):
    """Create new branch - Admin only"""
    if not is_admin(request.user):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse(
                {
                    "success": False,
                    "error": "You do not have permission to create branches",
                },
                status=403,
            )
        messages.error(request, "You do not have permission to create branches")
        return redirect("index")

    if request.method == "POST":
        form = BranchForm(request.POST)
        if form.is_valid():
            try:
                branch = form.save()
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return JsonResponse(
                        {
                            "success": True,
                            "message": "Branch created successfully",
                            "branch": {
                                "id": branch.id,
                                "name": branch.name,
                                "ip_count": 0,
                            },
                        }
                    )
                messages.success(request, "Branch created successfully")
                return redirect("branches_list")
            except Exception as e:
                logger.error(f"Error creating branch: {str(e)}")
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return JsonResponse({"success": False, "error": str(e)}, status=400)
                messages.error(request, f"Error: {str(e)}")
        else:
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return JsonResponse(
                    {"success": False, "errors": form.errors}, status=400
                )
    else:
        form = BranchForm()

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse({"error": "Method not allowed"}, status=405)

    return render(request, "ips/branch_form.html", {"form": form, "action": "Create"})


@login_required
@require_http_methods(["GET", "POST"])
def edit_branch(request, branch_id):
    """Edit existing branch - Admin only"""
    if not is_admin(request.user):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse(
                {
                    "success": False,
                    "error": "You do not have permission to edit branches",
                },
                status=403,
            )
        messages.error(request, "You do not have permission to edit branches")
        return redirect("index")

    branch = get_object_or_404(Branch, id=branch_id)

    if request.method == "POST":
        form = BranchForm(request.POST, instance=branch)
        if form.is_valid():
            try:
                branch = form.save()
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return JsonResponse(
                        {
                            "success": True,
                            "message": "Branch updated successfully",
                            "branch": {
                                "id": branch.id,
                                "name": branch.name,
                                "ip_count": branch.ip_count,
                            },
                        }
                    )
                messages.success(request, "Branch updated successfully")
                return redirect("branches_list")
            except Exception as e:
                logger.error(f"Error updating branch: {str(e)}")
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return JsonResponse({"success": False, "error": str(e)}, status=400)
                messages.error(request, f"Error: {str(e)}")
        else:
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return JsonResponse(
                    {"success": False, "errors": form.errors}, status=400
                )
    else:
        form = BranchForm(instance=branch)

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse(
            {
                "branch": {
                    "id": branch.id,
                    "name": branch.name,
                    "ip_count": branch.ip_count,
                }
            }
        )

    return render(
        request,
        "ips/branch_form.html",
        {"form": form, "branch": branch, "action": "Edit"},
    )


@login_required
@require_http_methods(["POST", "DELETE"])
def delete_branch(request, branch_id):
    """Delete branch - Admin only"""
    if not is_admin(request.user):
        return JsonResponse(
            {
                "success": False,
                "error": "You do not have permission to delete branches",
            },
            status=403,
        )

    branch = get_object_or_404(Branch, id=branch_id)

    # Check if branch has associated IPs
    ip_count = branch.ip_count
    if ip_count > 0:
        return JsonResponse(
            {
                "success": False,
                "error": f"Cannot delete branch with {ip_count} IP address(es). Please delete or reassign IPs first.",
            },
            status=400,
        )

    try:
        branch_name = branch.name
        branch.delete()
        return JsonResponse(
            {"success": True, "message": f'Branch "{branch_name}" deleted successfully'}
        )
    except Exception as e:
        logger.error(f"Error deleting branch: {str(e)}")
        return JsonResponse({"success": False, "error": str(e)}, status=500)


# ==================== END BRANCH CRUD ====================


@login_required
def get_ips_datatable(request):
    """DataTables server-side processing endpoint - OPTIMIZED"""
    try:
        draw = int(request.POST.get("draw", 1))
        start = int(request.POST.get("start", 0))
        length = int(request.POST.get("length", 10))
        search_value = request.POST.get("search[value]", "").strip()
        order_column = int(request.POST.get("order[0][column]", 0))
        order_dir = request.POST.get("order[0][dir]", "asc")
        branch_id = request.POST.get("branch_id")
        network = request.POST.get("network", "").strip()
        subnet_id = request.POST.get("subnet_id", "")

        if not branch_id:
            return JsonResponse(
                {"draw": draw, "recordsTotal": 0, "recordsFiltered": 0, "data": []}
            )

        # Base queryset with select_related to avoid N+1 queries
        queryset = IP.objects.filter(branch_id=branch_id).select_related(
            "device_type", "subnet", "branch"
        )

        # Apply network filter
        if network:
            network_prefix = ".".join(network.split(".")[:-1])
            queryset = queryset.filter(ip_address__startswith=network_prefix)

        # Apply subnet filter
        if subnet_id and subnet_id.isdigit():
            queryset = queryset.filter(subnet_id=int(subnet_id))

        # OPTIMIZATION: Only count once for total records (before search filter)
        total_records = queryset.count()

        # Apply search filter
        if search_value:
            queryset = queryset.filter(
                Q(ip_address__icontains=search_value)
                | Q(device_name__icontains=search_value)
                | Q(description__icontains=search_value)
                | Q(device_type__name__icontains=search_value)
            )
            filtered_records = queryset.count()
        else:
            filtered_records = total_records

        # OPTIMIZATION: Use database-level sorting for IP addresses
        order_columns = [
            "ip_address",
            "device_name",
            "device_type__name",
            "subnet__subnet_mask",
            "description",
        ]
        order_by = (
            order_columns[order_column]
            if order_column < len(order_columns)
            else "ip_address"
        )

        # Check if user can edit
        user_is_admin = is_admin(request.user)
        user_branch = get_user_branch(request.user)
        user_branch_id = user_branch.id if user_branch else None
        # OPTIMIZATION: For IP sorting, use inet ordering if supported, otherwise string sorting
        # For PostgreSQL, you can cast to inet type for proper IP sorting
        # For MySQL/SQLite, string sorting works reasonably well with proper format
        if order_column == 0:
            # Use database ordering with INET cast for PostgreSQL
            # or raw SQL for proper IP sorting
            from django.db import connection

            if "postgresql" in connection.vendor:
                order_by = "CAST(ip_address AS inet)"
                if order_dir == "desc":
                    order_by = f"-{order_by}"
                ips = queryset.extra(
                    select={"ip_order": "CAST(ip_address AS inet)"}
                ).order_by("ip_order" if order_dir == "asc" else "-ip_order")[
                    start : start + length
                ]
            else:
                # For non-PostgreSQL, use string sorting (works okay for IPs)
                # Or implement custom sorting
                if order_dir == "desc":
                    order_by = f"-{order_by}"
                ips = list(queryset)
                ips.sort(
                    key=lambda x: IP.ip_to_int(x.ip_address),
                    reverse=(order_dir == "desc"),
                )
                ips = ips[start : start + length]
        else:
            if order_dir == "desc":
                order_by = f"-{order_by}"
            ips = queryset.order_by(order_by)[start : start + length]

        data = []
        for ip in ips:
            # Determine if user can edit this IP
            can_edit = user_is_admin or (user_branch_id and user_branch_id == ip.branch.id)

            data.append(
                {
                    "id": ip.id,
                    "ip_address": ip.ip_address,
                    "device_name": ip.device_name,
                    "device_type": ip.device_type.name,
                    "device_type_id": ip.device_type.id,
                    "subnet_mask": ip.subnet.subnet_mask,
                    "subnet_id": ip.subnet.id,
                    "description": ip.description or "",
                    "branch_id": ip.branch.id,
                    "can_edit": can_edit,
                }
            )

        return JsonResponse(
            {
                "draw": draw,
                "recordsTotal": total_records,
                "recordsFiltered": filtered_records,
                "data": data,
            }
        )
    except Exception as e:
        logger.error(f"DataTables error: {str(e)}")
        return JsonResponse(
            {
                "draw": draw,
                "recordsTotal": 0,
                "recordsFiltered": 0,
                "data": [],
                "error": str(e),
            },
            status=500,
        )


@login_required
def get_networks(request):
    """API endpoint to get networks for a branch - PORTABLE VERSION"""
    branch_id = request.GET.get("branch_id")

    if not branch_id:
        return JsonResponse({"error": "Branch ID is required"}, status=400)

    try:
        from django.db.models import Count

        # Get distinct combinations of network prefix and subnet
        # Using values() to only load what we need
        ips_query = IP.objects.filter(branch_id=branch_id).values(
            "ip_address", "subnet_id", "subnet__prefix", "subnet__subnet_mask"
        )

        # Group networks efficiently
        network_dict = {}

        for ip_data in ips_query.iterator(chunk_size=5000):  # Process in chunks
            try:
                # Extract network (first 3 octets)
                parts = ip_data["ip_address"].split(".")
                if len(parts) == 4:
                    network = f"{parts[0]}.{parts[1]}.{parts[2]}.0"
                    subnet_id = ip_data["subnet_id"]
                    key = f"{network}_{subnet_id}"

                    if key not in network_dict:
                        network_dict[key] = {
                            "network": network,
                            "subnet_id": subnet_id,
                            "prefix": ip_data["subnet__prefix"],
                            "subnet_mask": ip_data["subnet__subnet_mask"],
                            "ip_count": 0,
                        }
                    network_dict[key]["ip_count"] += 1

            except (AttributeError, IndexError, KeyError) as e:
                logger.warning(f"Error processing IP data: {str(e)}")
                continue

        # Sort networks by IP value
        networks_list = sorted(
            network_dict.values(), key=lambda x: IP.ip_to_int(x["network"])
        )

        return JsonResponse(networks_list, safe=False)

    except Exception as e:
        logger.error(f"Error getting networks: {str(e)}", exc_info=True)
        return JsonResponse({"error": str(e)}, status=500)


@login_required
@require_http_methods(["GET", "POST"])
def edit_ip(request, ip_id):
    """Edit existing IP address with permission check"""
    ip = get_object_or_404(IP, id=ip_id)

    # Check permissions
    user_is_admin = is_admin(request.user)
    user_branch = get_user_branch(request.user)

    if not user_is_admin and (not user_branch or user_branch.id != ip.branch.id):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse(
                {
                    "success": False,
                    "error": "You do not have permission to edit this IP address",
                },
                status=403,
            )
        messages.error(request, "You do not have permission to edit this IP address")
        return redirect("index")

    if request.method == "POST":
        form = IPForm(request.POST, instance=ip)
        if form.is_valid():
            try:
                form.save()
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return JsonResponse(
                        {"success": True, "message": "IP address updated successfully"}
                    )
                messages.success(request, "IP address updated successfully")
                return redirect("index")
            except Exception as e:
                logger.error(f"Error updating IP: {str(e)}")
                if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                    return JsonResponse({"success": False, "error": str(e)}, status=400)
                messages.error(request, f"Error: {str(e)}")
        else:
            if request.headers.get("X-Requested-With") == "XMLHttpRequest":
                return JsonResponse(
                    {"success": False, "errors": form.errors}, status=400
                )
    else:
        form = IPForm(instance=ip)

    if request.headers.get("X-Requested-With") == "XMLHttpRequest":
        return JsonResponse(
            {
                "ip": {
                    "id": ip.id,
                    "ip_address": ip.ip_address,
                    "device_name": ip.device_name,
                    "device_type_id": ip.device_type.id,
                    "subnet_id": ip.subnet.id,
                    "branch_id": ip.branch.id,
                    "description": ip.description or "",
                }
            }
        )

    return render(request, "ips/ip_form.html", {"form": form, "ip": ip})


@login_required
def bulk_insert(request):
    """Bulk IP insert view - Admin only"""
    if not is_admin(request.user):
        messages.error(request, "You do not have permission to perform bulk inserts")
        return redirect("index")

    if request.method == "POST":
        try:
            data = json.loads(request.body)

            required_fields = [
                "start_ip",
                "end_ip",
                "branch_id",
                "subnet_id",
                "device_type_id",
            ]
            for field in required_fields:
                if not data.get(field):
                    return JsonResponse(
                        {"success": False, "error": f"Missing required field: {field}"},
                        status=400,
                    )

            start_ip = data["start_ip"]
            end_ip = data["end_ip"]
            branch_id = data["branch_id"]
            subnet_id = data["subnet_id"]
            device_type_id = data["device_type_id"]
            device_name_prefix = data.get("device_name_prefix", "Device")
            description = data.get("description", "Bulk inserted IP")
            skip_existing = data.get("skip_existing", True)

            try:
                validate_ipv4_address(start_ip)
                validate_ipv4_address(end_ip)
            except ValidationError:
                return JsonResponse(
                    {"success": False, "error": "Invalid IP address format"}, status=400
                )

            try:
                start_long = IP.ip_to_int(start_ip)
                end_long = IP.ip_to_int(end_ip)
            except Exception as e:
                return JsonResponse(
                    {
                        "success": False,
                        "error": f"Error parsing IP addresses: {str(e)}",
                    },
                    status=400,
                )

            if start_long > end_long:
                return JsonResponse(
                    {
                        "success": False,
                        "error": "Start IP must be less than or equal to End IP",
                    },
                    status=400,
                )

            total_ips = end_long - start_long + 1

            if total_ips > 5000000:
                return JsonResponse(
                    {
                        "success": False,
                        "error": f"Range too large. Maximum 5,000,000 IPs. Requested: {total_ips:,}",
                    },
                    status=400,
                )

            try:
                branch = Branch.objects.get(id=branch_id)
                subnet = Subnet.objects.get(id=subnet_id)
                device_type = DeviceType.objects.get(id=device_type_id)
            except (
                Branch.DoesNotExist,
                Subnet.DoesNotExist,
                DeviceType.DoesNotExist,
            ) as e:
                return JsonResponse(
                    {"success": False, "error": f"Invalid reference: {str(e)}"},
                    status=400,
                )

            inserted = 0
            skipped = 0
            errors = []

            existing_ips = set()
            if skip_existing:
                batch_size = 10000
                current = start_long
                while current <= end_long:
                    batch_end = min(current + batch_size, end_long + 1)
                    batch_ips = [IP.int_to_ip(i) for i in range(current, batch_end)]
                    existing = set(
                        IP.objects.filter(ip_address__in=batch_ips).values_list(
                            "ip_address", flat=True
                        )
                    )
                    existing_ips.update(existing)
                    current = batch_end

            batch_size = 1000
            current_long = start_long

            with transaction.atomic():
                batch = []

                while current_long <= end_long:
                    ip_address = IP.int_to_ip(current_long)

                    if skip_existing and ip_address in existing_ips:
                        skipped += 1
                        current_long += 1
                        continue

                    ip_suffix = ip_address.replace(".", "-")
                    device_name = f"{device_name_prefix}-{ip_suffix}"

                    batch.append(
                        IP(
                            ip_address=ip_address,
                            subnet=subnet,
                            device_name=device_name,
                            device_type=device_type,
                            branch=branch,
                            description=description,
                        )
                    )

                    if len(batch) >= batch_size:
                        try:
                            IP.objects.bulk_create(
                                batch, ignore_conflicts=skip_existing
                            )
                            inserted += len(batch)
                            batch = []
                        except Exception as e:
                            logger.error(f"Batch insert error: {str(e)}")
                            errors.append(str(e))

                    current_long += 1

                if batch:
                    try:
                        IP.objects.bulk_create(batch, ignore_conflicts=skip_existing)
                        inserted += len(batch)
                    except Exception as e:
                        logger.error(f"Final batch insert error: {str(e)}")
                        errors.append(str(e))

            return JsonResponse(
                {
                    "success": True,
                    "message": f"Successfully processed {total_ips:,} IP addresses",
                    "inserted": inserted,
                    "skipped": skipped,
                    "total_processed": total_ips,
                    "start_ip": start_ip,
                    "end_ip": end_ip,
                    "errors": errors,
                }
            )

        except json.JSONDecodeError:
            return JsonResponse(
                {"success": False, "error": "Invalid JSON data"}, status=400
            )
        except Exception as e:
            logger.error(f"Bulk insert error: {str(e)}")
            return JsonResponse({"success": False, "error": str(e)}, status=500)

    # GET request - show the form
    branches = Branch.objects.all().order_by("name")
    device_types = DeviceType.objects.all().order_by("name")
    subnets = Subnet.objects.all().order_by("prefix")

    context = {
        "branches": branches,
        "device_types": device_types,
        "subnets": subnets,
        "is_admin": True,  # ADD THIS LINE - User is already verified as admin
    }

    return render(request, "ips/bulk_insert.html", context)

@login_required
def ping_ip(request, ip_id):
    """Ping an IP address"""
    ip = get_object_or_404(IP, id=ip_id)

    try:
        # Determine the ping command based on OS
        param = "-n" if platform.system().lower() == "windows" else "-c"

        # Execute ping command (4 packets)
        command = ["ping", param, "4", ip.ip_address]
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            timeout=10,
            text=True,
        )

        # Check if ping was successful
        success = result.returncode == 0

        return JsonResponse(
            {
                "success": success,
                "ip_address": ip.ip_address,
                "device_name": ip.device_name,
                "output": result.stdout if success else result.stderr,
                "status": "online" if success else "offline",
            }
        )

    except subprocess.TimeoutExpired:
        return JsonResponse(
            {
                "success": False,
                "ip_address": ip.ip_address,
                "device_name": ip.device_name,
                "output": "Ping request timed out",
                "status": "timeout",
            }
        )
    except Exception as e:
        logger.error(f"Ping error: {str(e)}")
        return JsonResponse(
            {
                "success": False,
                "ip_address": ip.ip_address,
                "device_name": ip.device_name,
                "output": str(e),
                "status": "error",
            },
            status=500,
        )


@login_required
def get_device_types(request):
    """API endpoint to get device types"""
    try:
        device_types = list(DeviceType.objects.values("id", "name").order_by("name"))
        return JsonResponse(device_types, safe=False)
    except Exception as e:
        logger.error(f"Error getting device types: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)


@login_required
def get_subnets(request):
    """API endpoint to get subnets"""
    try:
        subnets = list(
            Subnet.objects.values("id", "prefix", "subnet_mask").order_by("prefix")
        )
        return JsonResponse(subnets, safe=False)
    except Exception as e:
        logger.error(f"Error getting subnets: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)


@login_required
def get_branches(request):
    """API endpoint to get branches"""
    try:
        branches = Branch.objects.all().order_by("name")

        branches_data = []
        for branch in branches:
            branches_data.append(
                {"id": branch.id, "name": branch.name, "ip_count": branch.ip_count}
            )

        return JsonResponse(branches_data, safe=False)
    except Exception as e:
        logger.error(f"Error getting branches: {str(e)}")
        return JsonResponse({"error": str(e)}, status=500)


# ==================== USER MANAGEMENT VIEWS ====================


@login_required
def users_list(request):
    """List all users - Admin only"""
    if not is_admin(request.user):
        messages.error(request, "You do not have permission to manage users")
        return redirect("index")

    users = (
        User.objects.select_related("profile", "profile__branch")
        .all()
        .order_by("username")
    )
    branches = Branch.objects.all().order_by("name")

    context = {
        "users": users,
        "branches": branches,
        "is_admin": True,
    }

    return render(request, "ips/users_list.html", context)


@login_required
@require_http_methods(["GET", "POST"])
def create_user(request):
    """Create new user - Admin only"""
    if not is_admin(request.user):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse(
                {
                    "success": False,
                    "error": "You do not have permission to create users",
                },
                status=403,
            )
        messages.error(request, "You do not have permission to create users")
        return redirect("index")

    if request.method == "POST":
        try:
            username = request.POST.get("username", "").strip()
            email = request.POST.get("email", "").strip()
            first_name = request.POST.get("first_name", "").strip()
            last_name = request.POST.get("last_name", "").strip()
            password1 = request.POST.get("password1", "")
            password2 = request.POST.get("password2", "")
            is_admin_user = request.POST.get("is_admin") == "on"
            branch_id = request.POST.get("branch", "")

            # Validation
            if not username:
                return JsonResponse(
                    {
                        "success": False,
                        "errors": {"username": ["Username is required"]},
                    },
                    status=400,
                )

            if User.objects.filter(username=username).exists():
                return JsonResponse(
                    {
                        "success": False,
                        "errors": {"username": ["Username already exists"]},
                    },
                    status=400,
                )

            if not password1 or not password2:
                return JsonResponse(
                    {
                        "success": False,
                        "errors": {"password1": ["Password is required"]},
                    },
                    status=400,
                )

            if password1 != password2:
                return JsonResponse(
                    {
                        "success": False,
                        "errors": {"password2": ["Passwords do not match"]},
                    },
                    status=400,
                )

            if len(password1) < 8:
                return JsonResponse(
                    {
                        "success": False,
                        "errors": {
                            "password1": ["Password must be at least 8 characters"]
                        },
                    },
                    status=400,
                )

            # Create user
            with transaction.atomic():
                user = User.objects.create_user(
                    username=username,
                    email=email,
                    first_name=first_name,
                    last_name=last_name,
                    password=password1,
                )

                # Create or update profile
                profile, created = UserProfile.objects.get_or_create(user=user)
                profile.is_admin = is_admin_user

                if branch_id and not is_admin_user:
                    try:
                        profile.branch = Branch.objects.get(id=branch_id)
                    except Branch.DoesNotExist:
                        pass
                else:
                    profile.branch = None

                profile.save()

            return JsonResponse(
                {"success": True, "message": f'User "{username}" created successfully'}
            )

        except Exception as e:
            logger.error(f"Error creating user: {str(e)}")
            return JsonResponse({"success": False, "error": str(e)}, status=500)

    return JsonResponse({"error": "Method not allowed"}, status=405)


@login_required
@require_http_methods(["GET", "POST"])
def edit_user(request, user_id):
    """Edit existing user - Admin only"""
    if not is_admin(request.user):
        if request.headers.get("X-Requested-With") == "XMLHttpRequest":
            return JsonResponse(
                {"success": False, "error": "You do not have permission to edit users"},
                status=403,
            )
        messages.error(request, "You do not have permission to edit users")
        return redirect("index")

    user = get_object_or_404(User, id=user_id)

    if (
        request.method == "GET"
        and request.headers.get("X-Requested-With") == "XMLHttpRequest"
    ):
        # Return user data for editing
        profile = getattr(user, "profile", None)
        return JsonResponse(
            {
                "user": {
                    "id": user.id,
                    "username": user.username,
                    "email": user.email or "",
                    "first_name": user.first_name or "",
                    "last_name": user.last_name or "",
                    "is_admin": profile.is_admin if profile else False,
                    "branch_id": (
                        profile.branch.id if profile and profile.branch else None
                    ),
                    "is_active": user.is_active,
                }
            }
        )

    if request.method == "POST":
        try:
            username = request.POST.get("username", "").strip()
            email = request.POST.get("email", "").strip()
            first_name = request.POST.get("first_name", "").strip()
            last_name = request.POST.get("last_name", "").strip()
            is_admin_user = request.POST.get("is_admin") == "on"
            is_active = request.POST.get("is_active") == "on"
            branch_id = request.POST.get("branch", "")

            # Validation
            if not username:
                return JsonResponse(
                    {
                        "success": False,
                        "errors": {"username": ["Username is required"]},
                    },
                    status=400,
                )

            if User.objects.filter(username=username).exclude(id=user_id).exists():
                return JsonResponse(
                    {
                        "success": False,
                        "errors": {"username": ["Username already exists"]},
                    },
                    status=400,
                )

            # Update user
            with transaction.atomic():
                user.username = username
                user.email = email
                user.first_name = first_name
                user.last_name = last_name
                user.is_active = is_active
                user.save()

                # Update profile
                profile, created = UserProfile.objects.get_or_create(user=user)
                profile.is_admin = is_admin_user

                if branch_id and not is_admin_user:
                    try:
                        profile.branch = Branch.objects.get(id=branch_id)
                    except Branch.DoesNotExist:
                        profile.branch = None
                else:
                    profile.branch = None

                profile.save()

            return JsonResponse(
                {"success": True, "message": f'User "{username}" updated successfully'}
            )

        except Exception as e:
            logger.error(f"Error updating user: {str(e)}")
            return JsonResponse({"success": False, "error": str(e)}, status=500)

    return JsonResponse({"error": "Method not allowed"}, status=405)


@login_required
@require_http_methods(["POST"])
def delete_user(request, user_id):
    """Delete user - Admin only"""
    if not is_admin(request.user):
        return JsonResponse(
            {"success": False, "error": "You do not have permission to delete users"},
            status=403,
        )

    user = get_object_or_404(User, id=user_id)

    # Prevent deleting self
    if user.id == request.user.id:
        return JsonResponse(
            {"success": False, "error": "You cannot delete your own account"},
            status=400,
        )

    # Prevent deleting superuser
    if user.is_superuser:
        return JsonResponse(
            {"success": False, "error": "Cannot delete superuser account"}, status=400
        )

    try:
        username = user.username
        user.delete()
        return JsonResponse(
            {"success": True, "message": f'User "{username}" deleted successfully'}
        )
    except Exception as e:
        logger.error(f"Error deleting user: {str(e)}")
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def change_user_password(request, user_id):
    """Change user password - Admin only"""
    if not is_admin(request.user):
        return JsonResponse(
            {
                "success": False,
                "error": "You do not have permission to change user passwords",
            },
            status=403,
        )

    user = get_object_or_404(User, id=user_id)

    try:
        data = json.loads(request.body)
        new_password = data.get("new_password", "")

        if not new_password:
            return JsonResponse(
                {"success": False, "error": "New password is required"}, status=400
            )

        if len(new_password) < 8:
            return JsonResponse(
                {"success": False, "error": "Password must be at least 8 characters"},
                status=400,
            )

        user.set_password(new_password)
        user.save()

        return JsonResponse(
            {
                "success": True,
                "message": f'Password changed successfully for user "{user.username}"',
            }
        )

    except json.JSONDecodeError:
        return JsonResponse(
            {"success": False, "error": "Invalid JSON data"}, status=400
        )
    except Exception as e:
        logger.error(f"Error changing password: {str(e)}")
        return JsonResponse({"success": False, "error": str(e)}, status=500)


@login_required
@require_http_methods(["POST"])
def toggle_user_status(request, user_id):
    """Toggle user active status - Admin only"""
    if not is_admin(request.user):
        return JsonResponse(
            {
                "success": False,
                "error": "You do not have permission to change user status",
            },
            status=403,
        )

    user = get_object_or_404(User, id=user_id)

    # Prevent toggling self
    if user.id == request.user.id:
        return JsonResponse(
            {"success": False, "error": "You cannot change your own status"}, status=400
        )

    try:
        user.is_active = not user.is_active
        user.save()

        status = "activated" if user.is_active else "deactivated"
        return JsonResponse(
            {
                "success": True,
                "message": f'User "{user.username}" {status} successfully',
            }
        )

    except Exception as e:
        logger.error(f"Error toggling user status: {str(e)}")
        return JsonResponse({"success": False, "error": str(e)}, status=500)

@login_required
@require_http_methods(["POST"])
def bulk_delete_ips(request):
    """Bulk delete IP addresses - Admin only"""
    if not is_admin(request.user):
        return JsonResponse(
            {
                "success": False,
                "error": "You do not have permission to delete IP addresses",
            },
            status=403,
        )

    try:
        data = json.loads(request.body)
        ip_ids = data.get("ip_ids", [])

        if not ip_ids:
            return JsonResponse(
                {"success": False, "error": "No IP addresses selected"}, status=400
            )

        if not isinstance(ip_ids, list):
            return JsonResponse(
                {"success": False, "error": "Invalid data format"}, status=400
            )

        # Validate that all IDs are integers
        try:
            ip_ids = [int(ip_id) for ip_id in ip_ids]
        except (ValueError, TypeError):
            return JsonResponse(
                {"success": False, "error": "Invalid IP ID format"}, status=400
            )

        # Get the IPs to delete
        ips_to_delete = IP.objects.filter(id__in=ip_ids)
        deleted_count = ips_to_delete.count()

        if deleted_count == 0:
            return JsonResponse(
                {"success": False, "error": "No IP addresses found to delete"},
                status=404,
            )

        # Log the deletion for audit purposes
        logger.info(
            f"User {request.user.username} is deleting {deleted_count} IP address(es): {ip_ids}"
        )

        # Perform the deletion
        with transaction.atomic():
            ips_to_delete.delete()

        return JsonResponse(
            {
                "success": True,
                "message": f"Successfully deleted {deleted_count} IP address(es)",
                "deleted_count": deleted_count,
            }
        )

    except json.JSONDecodeError:
        return JsonResponse(
            {"success": False, "error": "Invalid JSON data"}, status=400
        )
    except Exception as e:
        logger.error(f"Error in bulk delete: {str(e)}", exc_info=True)
        return JsonResponse({"success": False, "error": str(e)}, status=500)
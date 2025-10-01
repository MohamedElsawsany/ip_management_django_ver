# ips/views.py - Bug-Fixed Version
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
import json
import logging

from .models import Branch, DeviceType, Subnet, IP
from .forms import IPForm, BulkIPForm

logger = logging.getLogger(__name__)


def login_view(request):
    """User login view with proper error handling"""
    if request.user.is_authenticated:
        return redirect('index')
    
    if request.method == 'POST':
        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        
        if not username or not password:
            messages.error(request, 'Please provide both username and password')
            return render(request, 'ips/login.html')
        
        user = authenticate(request, username=username, password=password)
        
        if user is not None:
            login(request, user)
            next_url = request.GET.get('next', 'index')
            # Prevent open redirect vulnerability
            if not next_url.startswith('/'):
                next_url = 'index'
            return redirect(next_url)
        else:
            messages.error(request, 'Invalid username or password')
    
    return render(request, 'ips/login.html')


@login_required
def logout_view(request):
    """User logout view"""
    logout(request)
    messages.success(request, 'You have been logged out successfully')
    return redirect('login')


@login_required
def index(request):
    """Main dashboard view with improved error handling"""
    try:
        # Get branches and let the property handle ip_count
        branches = Branch.objects.all().order_by('name')
        
        context = {
            'branches': branches
        }
        
        return render(request, 'ips/index.html', context)
        
    except Exception as e:
        logger.error(f"Error loading dashboard: {str(e)}", exc_info=True)
        messages.error(request, f'Error loading dashboard: {str(e)}')
        
        # Return empty context to prevent template errors
        context = {
            'branches': []
        }
        return render(request, 'ips/index.html', context)

@login_required
def get_networks(request):
    """API endpoint to get networks for a branch with proper error handling"""
    branch_id = request.GET.get('branch_id')
    
    if not branch_id:
        return JsonResponse({'error': 'Branch ID is required'}, status=400)
    
    try:
        # Verify branch exists
        branch = get_object_or_404(Branch, id=branch_id)
        
        # Get all IPs for the branch
        ips = IP.objects.filter(branch_id=branch_id).select_related('subnet')
        
        # Group by network
        network_dict = {}
        for ip in ips:
            try:
                # Extract network address (first 3 octets)
                network = '.'.join(ip.ip_address.split('.')[:-1]) + '.0'
                key = f"{network}_{ip.subnet.id}"
                
                if key not in network_dict:
                    network_dict[key] = {
                        'network': network,
                        'subnet_id': ip.subnet.id,
                        'prefix': ip.subnet.prefix,
                        'subnet_mask': ip.subnet.subnet_mask,
                        'ip_count': 0
                    }
                network_dict[key]['ip_count'] += 1
            except Exception as e:
                logger.warning(f"Error processing IP {ip.ip_address}: {str(e)}")
                continue
        
        # Sort networks by IP address
        networks_list = sorted(
            network_dict.values(), 
            key=lambda x: IP.ip_to_int(x['network'])
        )
        
        return JsonResponse(networks_list, safe=False)
    except Exception as e:
        logger.error(f"Error getting networks: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def get_ips_datatable(request):
    """DataTables server-side processing endpoint with improved error handling"""
    try:
        draw = int(request.POST.get('draw', 1))
        start = int(request.POST.get('start', 0))
        length = int(request.POST.get('length', 10))
        search_value = request.POST.get('search[value]', '').strip()
        order_column = int(request.POST.get('order[0][column]', 0))
        order_dir = request.POST.get('order[0][dir]', 'asc')
        branch_id = request.POST.get('branch_id')
        network = request.POST.get('network', '').strip()
        subnet_id = request.POST.get('subnet_id', '')

        if not branch_id:
            return JsonResponse({
                'draw': draw,
                'recordsTotal': 0,
                'recordsFiltered': 0,
                'data': []
            })

        # Base queryset with proper joins
        queryset = IP.objects.filter(
            branch_id=branch_id
        ).select_related('device_type', 'subnet', 'branch')

        # Apply network filter
        if network:
            network_prefix = '.'.join(network.split('.')[:-1])
            queryset = queryset.filter(ip_address__startswith=network_prefix)

        # Apply subnet filter
        if subnet_id and subnet_id.isdigit():
            queryset = queryset.filter(subnet_id=int(subnet_id))

        # Total records before filtering
        total_records = queryset.count()

        # Apply search
        if search_value:
            queryset = queryset.filter(
                Q(ip_address__icontains=search_value) |
                Q(device_name__icontains=search_value) |
                Q(description__icontains=search_value) |
                Q(device_type__name__icontains=search_value)
            )

        filtered_records = queryset.count()

        # Apply ordering
        order_columns = [
            'ip_address', 'device_name', 'device_type__name', 
            'subnet__subnet_mask', 'description'
        ]
        order_by = order_columns[order_column] if order_column < len(order_columns) else 'ip_address'
        
        # For IP address sorting, use custom method
        if order_column == 0:
            ips = list(queryset)
            ips.sort(
                key=lambda x: IP.ip_to_int(x.ip_address), 
                reverse=(order_dir == 'desc')
            )
            ips = ips[start:start + length]
        else:
            if order_dir == 'desc':
                order_by = f'-{order_by}'
            ips = queryset.order_by(order_by)[start:start + length]

        # Format data
        data = []
        for ip in ips:
            data.append({
                'id': ip.id,
                'ip_address': ip.ip_address,
                'device_name': ip.device_name,
                'device_type': ip.device_type.name,
                'device_type_id': ip.device_type.id,
                'subnet_mask': ip.subnet.subnet_mask,
                'subnet_id': ip.subnet.id,
                'description': ip.description or ''
            })

        return JsonResponse({
            'draw': draw,
            'recordsTotal': total_records,
            'recordsFiltered': filtered_records,
            'data': data
        })
    except Exception as e:
        logger.error(f"DataTables error: {str(e)}")
        return JsonResponse({
            'draw': draw,
            'recordsTotal': 0,
            'recordsFiltered': 0,
            'data': [],
            'error': str(e)
        }, status=500)


@login_required
@require_http_methods(["GET", "POST"])
def add_ip(request):
    """Add new IP address with validation"""
    if request.method == 'POST':
        form = IPForm(request.POST)
        if form.is_valid():
            try:
                # Additional validation
                ip_address = form.cleaned_data['ip_address']
                validate_ipv4_address(ip_address)
                
                ip = form.save()
                
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'success': True, 
                        'message': 'IP address added successfully'
                    })
                messages.success(request, 'IP address added successfully')
                return redirect('index')
            except ValidationError as e:
                error_msg = str(e.message) if hasattr(e, 'message') else str(e)
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'success': False, 
                        'error': error_msg
                    }, status=400)
                messages.error(request, error_msg)
            except IntegrityError:
                error_msg = 'This IP address already exists'
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'success': False, 
                        'error': error_msg
                    }, status=400)
                messages.error(request, error_msg)
            except Exception as e:
                logger.error(f"Error adding IP: {str(e)}")
                error_msg = f'Error: {str(e)}'
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'success': False, 
                        'error': error_msg
                    }, status=400)
                messages.error(request, error_msg)
        else:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': False, 
                    'errors': form.errors
                }, status=400)
            messages.error(request, 'Please correct the errors below')
    else:
        form = IPForm()
    
    return render(request, 'ips/ip_form.html', {'form': form})


@login_required
@require_http_methods(["GET", "POST"])
def edit_ip(request, ip_id):
    """Edit existing IP address"""
    ip = get_object_or_404(IP, id=ip_id)
    
    if request.method == 'POST':
        form = IPForm(request.POST, instance=ip)
        if form.is_valid():
            try:
                form.save()
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'success': True, 
                        'message': 'IP address updated successfully'
                    })
                messages.success(request, 'IP address updated successfully')
                return redirect('index')
            except Exception as e:
                logger.error(f"Error updating IP: {str(e)}")
                if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                    return JsonResponse({
                        'success': False, 
                        'error': str(e)
                    }, status=400)
                messages.error(request, f'Error: {str(e)}')
        else:
            if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
                return JsonResponse({
                    'success': False, 
                    'errors': form.errors
                }, status=400)
    else:
        form = IPForm(instance=ip)
    
    if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
        return JsonResponse({
            'ip': {
                'id': ip.id,
                'ip_address': ip.ip_address,
                'device_name': ip.device_name,
                'device_type_id': ip.device_type.id,
                'subnet_id': ip.subnet.id,
                'branch_id': ip.branch.id,
                'description': ip.description or ''
            }
        })
    
    return render(request, 'ips/ip_form.html', {'form': form, 'ip': ip})


@login_required
@require_http_methods(["POST", "DELETE"])
def delete_ip(request, ip_id):
    """Delete IP address"""
    ip = get_object_or_404(IP, id=ip_id)
    
    try:
        ip.delete()
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'success': True, 
                'message': 'IP address deleted successfully'
            })
        messages.success(request, 'IP address deleted successfully')
    except Exception as e:
        logger.error(f"Error deleting IP: {str(e)}")
        if request.headers.get('X-Requested-With') == 'XMLHttpRequest':
            return JsonResponse({
                'success': False, 
                'error': str(e)
            }, status=400)
        messages.error(request, f'Error: {str(e)}')
    
    return redirect('index')


@login_required
def bulk_insert(request):
    """Bulk IP insert view with comprehensive error handling"""
    if request.method == 'POST':
        try:
            data = json.loads(request.body)
            
            # Validate required fields
            required_fields = [
                'start_ip', 'end_ip', 'branch_id', 
                'subnet_id', 'device_type_id'
            ]
            for field in required_fields:
                if not data.get(field):
                    return JsonResponse({
                        'success': False, 
                        'error': f'Missing required field: {field}'
                    }, status=400)
            
            start_ip = data['start_ip']
            end_ip = data['end_ip']
            branch_id = data['branch_id']
            subnet_id = data['subnet_id']
            device_type_id = data['device_type_id']
            device_name_prefix = data.get('device_name_prefix', 'Device')
            description = data.get('description', 'Bulk inserted IP')
            skip_existing = data.get('skip_existing', True)
            
            # Validate IP addresses
            try:
                validate_ipv4_address(start_ip)
                validate_ipv4_address(end_ip)
            except ValidationError:
                return JsonResponse({
                    'success': False, 
                    'error': 'Invalid IP address format'
                }, status=400)
            
            # Convert IPs to integers
            try:
                start_long = IP.ip_to_int(start_ip)
                end_long = IP.ip_to_int(end_ip)
            except Exception as e:
                return JsonResponse({
                    'success': False, 
                    'error': f'Error parsing IP addresses: {str(e)}'
                }, status=400)
            
            if start_long > end_long:
                return JsonResponse({
                    'success': False, 
                    'error': 'Start IP must be less than or equal to End IP'
                }, status=400)
            
            total_ips = end_long - start_long + 1
            
            # Check maximum limit
            if total_ips > 5000000:
                return JsonResponse({
                    'success': False,
                    'error': f'Range too large. Maximum 5,000,000 IPs. Requested: {total_ips:,}'
                }, status=400)
            
            # Get related objects
            try:
                branch = Branch.objects.get(id=branch_id)
                subnet = Subnet.objects.get(id=subnet_id)
                device_type = DeviceType.objects.get(id=device_type_id)
            except (Branch.DoesNotExist, Subnet.DoesNotExist, DeviceType.DoesNotExist) as e:
                return JsonResponse({
                    'success': False,
                    'error': f'Invalid reference: {str(e)}'
                }, status=400)
            
            inserted = 0
            skipped = 0
            errors = []
            
            # Get existing IPs in the range (for skip_existing)
            existing_ips = set()
            if skip_existing:
                # Check in batches to avoid memory issues
                batch_size = 10000
                current = start_long
                while current <= end_long:
                    batch_end = min(current + batch_size, end_long + 1)
                    batch_ips = [
                        IP.int_to_ip(i) for i in range(current, batch_end)
                    ]
                    existing = set(
                        IP.objects.filter(
                            ip_address__in=batch_ips
                        ).values_list('ip_address', flat=True)
                    )
                    existing_ips.update(existing)
                    current = batch_end
            
            # Process in batches
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
                    
                    ip_suffix = ip_address.replace('.', '-')
                    device_name = f"{device_name_prefix}-{ip_suffix}"
                    
                    batch.append(IP(
                        ip_address=ip_address,
                        subnet=subnet,
                        device_name=device_name,
                        device_type=device_type,
                        branch=branch,
                        description=description
                    ))
                    
                    if len(batch) >= batch_size:
                        try:
                            IP.objects.bulk_create(
                                batch, 
                                ignore_conflicts=skip_existing
                            )
                            inserted += len(batch)
                            batch = []
                        except Exception as e:
                            logger.error(f"Batch insert error: {str(e)}")
                            errors.append(str(e))
                    
                    current_long += 1
                
                # Insert remaining
                if batch:
                    try:
                        IP.objects.bulk_create(
                            batch, 
                            ignore_conflicts=skip_existing
                        )
                        inserted += len(batch)
                    except Exception as e:
                        logger.error(f"Final batch insert error: {str(e)}")
                        errors.append(str(e))
            
            return JsonResponse({
                'success': True,
                'message': f'Successfully processed {total_ips:,} IP addresses',
                'inserted': inserted,
                'skipped': skipped,
                'total_processed': total_ips,
                'start_ip': start_ip,
                'end_ip': end_ip,
                'errors': errors
            })
            
        except json.JSONDecodeError:
            return JsonResponse({
                'success': False, 
                'error': 'Invalid JSON data'
            }, status=400)
        except Exception as e:
            logger.error(f"Bulk insert error: {str(e)}")
            return JsonResponse({
                'success': False, 
                'error': str(e)
            }, status=500)
    
    # GET request - show form
    branches = Branch.objects.all().order_by('name')
    device_types = DeviceType.objects.all().order_by('name')
    subnets = Subnet.objects.all().order_by('prefix')
    
    return render(request, 'ips/bulk_insert.html', {
        'branches': branches,
        'device_types': device_types,
        'subnets': subnets
    })


@login_required
def get_device_types(request):
    """API endpoint to get device types"""
    try:
        device_types = list(
            DeviceType.objects.values('id', 'name').order_by('name')
        )
        return JsonResponse(device_types, safe=False)
    except Exception as e:
        logger.error(f"Error getting device types: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def get_subnets(request):
    """API endpoint to get subnets"""
    try:
        subnets = list(
            Subnet.objects.values('id', 'prefix', 'subnet_mask').order_by('prefix')
        )
        return JsonResponse(subnets, safe=False)
    except Exception as e:
        logger.error(f"Error getting subnets: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)


@login_required
def get_branches(request):
    """API endpoint to get branches"""
    try:
        branches = Branch.objects.all().order_by('name')
        
        # Manually build the response with ip_count property
        branches_data = []
        for branch in branches:
            branches_data.append({
                'id': branch.id,
                'name': branch.name,
                'ip_count': branch.ip_count  # This uses the property from the model
            })
        
        return JsonResponse(branches_data, safe=False)
    except Exception as e:
        logger.error(f"Error getting branches: {str(e)}")
        return JsonResponse({'error': str(e)}, status=500)
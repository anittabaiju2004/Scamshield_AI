
import re

from datetime import timedelta
from itertools import chain

from django.contrib import messages
from django.contrib.auth import (
    authenticate,
    get_user_model,
    login as auth_login,
    logout as auth_logout,
)
from django.contrib.auth.decorators import login_required
from django.contrib.auth.hashers import check_password
from django.contrib.auth.password_validation import validate_password

from django.core.exceptions import ValidationError
from django.core.paginator import Paginator

from django.db import IntegrityError
from django.db.models import Avg, Count, Q
from django.db.models.functions import TruncDate

from django.http import HttpResponseForbidden

from django.shortcuts import (
    render,
    redirect,
    get_object_or_404,
)

from django.utils import timezone
from django.utils.http import url_has_allowed_host_and_scheme

from django.views.decorators.http import require_POST

from .models import User, ScanHistory, URLScanHistory
from .ml_service import predict_message
from .services.url_scanner import scan_url


User = get_user_model()

# Validation patterns (kept in sync with the checks in register.html)
NAME_RE = re.compile(r"^[A-Za-z\s.'-]+$")
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.]{3,20}$")
EMAIL_RE = re.compile(r"^[^\s@]+@[^\s@]+\.[^\s@]+$")
PHONE_RE = re.compile(r"^\+?\d{10,15}$")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def admin_required(view_func):
    @login_required
    def wrapper(request, *args, **kwargs):
        if request.user.role != 'ADMIN':
            return HttpResponseForbidden("You are not authorized to access this page.")

        return view_func(request, *args, **kwargs)

    return wrapper

def _is_admin(user):
    """Admins = role ADMIN, or Django staff/superusers."""
    return user.role == 'ADMIN' or user.is_superuser or user.is_staff


def _dashboard_for(user):
    """URL name of the dashboard this user should land on."""
    return 'admin_dashboard' if _is_admin(user) else 'user_dashboard'


def _password_error(password):
    """Return the first password-rule error, or None if the password is OK."""
    if not password:
        return "Password is required."
    if len(password) < 8:
        return "Password must contain at least 8 characters."
    if not re.search(r'[A-Z]', password):
        return "Password must contain an uppercase letter."
    if not re.search(r'\d', password):
        return "Password must contain a number."
    if not re.search(r'[^A-Za-z0-9]', password):
        return "Password must contain a special character."
    return None


# ---------------------------------------------------------------------------
# Home
# ---------------------------------------------------------------------------

def home(request):
    return render(request, 'home.html')


# ---------------------------------------------------------------------------
# Register
# ---------------------------------------------------------------------------
def register(request):
    if request.user.is_authenticated:
        return redirect(_dashboard_for(request.user))

    if request.method != 'POST':
        return render(request, 'register.html')

    full_name = request.POST.get('fullName', '').strip()
    username = request.POST.get('username', '').strip()
    email = request.POST.get('email', '').strip().lower()
    phone = request.POST.get('phone', '').strip()
    address = request.POST.get('address', '').strip()

    password = request.POST.get('password', '')
    confirm_password = request.POST.get('confirmPassword', '')
    terms = request.POST.get('terms')

    # Sent back to the template so the user doesn't have to retype them
    context = {
        'full_name': full_name,
        'username': username,
        'email': email,
        'phone': phone,
        'address': address,
    }

    errors = {}

    # Full name
    if not full_name:
        errors['fullName'] = "Full name is required."
    elif len(full_name) < 2:
        errors['fullName'] = "Name must contain at least 2 characters."
    elif not NAME_RE.match(full_name):
        errors['fullName'] = "Name contains invalid characters."

    # Username
    if not username:
        errors['username'] = "Username is required."
    elif not USERNAME_RE.match(username):
        errors['username'] = (
            "Username must be 3–20 characters: letters, numbers, _ or ."
        )
    elif User.objects.filter(username__iexact=username).exists():
        errors['username'] = "Username already exists."

    # Email
    if not email:
        errors['email'] = "Email is required."
    elif not EMAIL_RE.match(email):
        errors['email'] = "Enter a valid email address."
    elif User.objects.filter(email__iexact=email).exists():
        errors['email'] = "Email already registered."

    # Phone (optional)
    phone_clean = re.sub(r'[\s()-]', '', phone) or None

    if phone_clean and not PHONE_RE.match(phone_clean):
        errors['phone'] = "Enter a valid phone number."

    # Password validation
    pwd_error = _password_error(password)

    if pwd_error:
        errors['password'] = pwd_error
    else:
        try:
            validate_password(
                password,
                user=User(username=username, email=email)
            )
        except ValidationError as e:
            errors['password'] = " ".join(e.messages)

    # Confirm password
    if not confirm_password:
        errors['confirmPassword'] = "Please confirm your password."
    elif password != confirm_password:
        errors['confirmPassword'] = "Passwords do not match."

    # Terms
    if not terms:
        errors['terms'] = "You must accept the Terms & Conditions."

    # Return validation errors
    if errors:
        context['errors'] = errors
        return render(request, 'register.html', context)

    # Create user
    try:
        User.objects.create_user(
            username=username,
            email=email,
            password=password,
            full_name=full_name,
            phone=phone_clean,
            address=address or None,
            role='USER',
        )

    except IntegrityError:
        messages.error(request, "Username or email already exists.")
        return render(request, 'register.html', context)

    messages.success(
        request,
        "Registration successful! Please login."
    )

    return redirect('login')
# ---------------------------------------------------------------------------
# Login
# ---------------------------------------------------------------------------

def login(request):

    if request.user.is_authenticated:
        if request.user.role == 'ADMIN' or request.user.is_superuser or request.user.is_staff:
            return redirect('admin_dashboard')

        return redirect('user_dashboard')

    if request.method == 'POST':

        username = request.POST.get('username', '').strip()
        password = request.POST.get('password', '')
        remember = request.POST.get('remember')

        if not username or not password:
            messages.error(request, "Username and password are required.")
            return render(request, 'login.html', {'username': username})

        # Find user by username
        user_obj = User.objects.filter(username=username).first()

        # Check username and password
        if user_obj and check_password(password, user_obj.password):

            # Check account status
            if not user_obj.is_active:
                messages.error(request, "Your account is inactive. Please contact the administrator.")
                return render(request, 'login.html', {'username': username})

            # Authenticate active user
            user = authenticate(
                request,
                username=username,
                password=password
            )

            if user is not None:

                auth_login(request, user)

                # Remember Me
                if not remember:
                    request.session.set_expiry(0)

                messages.success(request, "Login successful! Welcome back.")

                # Role-based redirection
                if user.role == 'ADMIN' or user.is_superuser or user.is_staff:
                    return redirect('admin_dashboard')

                return redirect('user_dashboard')

        messages.error(request, "Invalid username or password.")
        return render(request, 'login.html', {'username': username})

    return render(request, 'login.html')

# ---------------------------------------------------------------------------
# Dashboards
# ---------------------------------------------------------------------------

# Map each model's result to one shared risk level
MESSAGE_LEVELS = {'Legitimate': 'safe', 'Spam': 'suspicious', 'Scam / Phishing': 'high'}
URL_LEVELS = {'Low Risk': 'safe', 'Suspicious': 'suspicious', 'High Risk': 'high'}
 
 
def _level_counts(queryset, level_map):
    """{'safe': n, 'suspicious': n, 'high': n} in a single GROUP BY query."""
    counts = {'safe': 0, 'suspicious': 0, 'high': 0}
    rows = queryset.order_by().values('result').annotate(n=Count('id'))
    for row in rows:
        level = level_map.get(row['result'])
        if level:
            counts[level] += row['n']
    return counts
 
 
def _percent(part, total):
    return round(part / total * 100, 1) if total else 0
 
 
@login_required
def user_dashboard(request):
    # Admins have their own dashboard
    if _is_admin(request.user):
        return redirect('admin_dashboard')
 
    message_scans = ScanHistory.objects.filter(user=request.user)
    url_scans = URLScanHistory.objects.filter(user=request.user)
 
    # ---------------- COUNTS ----------------
    message_total = message_scans.count()
    url_total = url_scans.count()
    total_scans = message_total + url_total
 
    msg_levels = _level_counts(message_scans, MESSAGE_LEVELS)
    url_levels = _level_counts(url_scans, URL_LEVELS)
 
    safe_count = msg_levels['safe'] + url_levels['safe']
    suspicious_count = msg_levels['suspicious'] + url_levels['suspicious']
    high_risk_count = msg_levels['high'] + url_levels['high']
 
    # ---------------- LAST 7 DAYS (for the bar chart) ----------------
    today = timezone.localdate()
    start = today - timedelta(days=6)
    days = [start + timedelta(days=i) for i in range(7)]
    week = {d: {'safe': 0, 'suspicious': 0, 'high': 0} for d in days}
 
    for qs, level_map in ((message_scans, MESSAGE_LEVELS), (url_scans, URL_LEVELS)):
        rows = (
            qs.filter(created_at__date__gte=start)
              .annotate(day=TruncDate('created_at'))
              .order_by()
              .values('day', 'result')
              .annotate(n=Count('id'))
        )
        for row in rows:
            level = level_map.get(row['result'])
            if level and row['day'] in week:
                week[row['day']][level] += row['n']
 
    weekly_chart = [
        {'day': d.strftime('%a'), 'date': d.strftime('%d %b'), 'is_today': d == today, **week[d]}
        for d in days
    ]
    week_total = sum(d['safe'] + d['suspicious'] + d['high'] for d in weekly_chart)
 
    # ---------------- RECENT HISTORY (messages + URLs) ----------------
    recent_messages = [
        {
            'id': s.id,
            'code': f'SCN-{s.id:04d}',
            'type': 'Message',
            'content': s.message,
            'result': s.result,
            'level': MESSAGE_LEVELS.get(s.result, 'suspicious'),
            'score': s.confidence,
            'score_label': 'Confidence',
            'created_at': s.created_at,
            'detail_url': 'scan_detail',
        }
        for s in message_scans[:10]
    ]
    recent_urls = [
        {
            'id': s.id,
            'code': f'URL-{s.id:04d}',
            'type': 'URL',
            'content': s.url,
            'result': s.result,
            'level': URL_LEVELS.get(s.result, 'suspicious'),
            'score': s.risk_score,
            'score_label': 'Risk score',
            'created_at': s.created_at,
            'detail_url': 'url_scan_detail',
        }
        for s in url_scans[:10]
    ]
    recent_history = sorted(
        chain(recent_messages, recent_urls),
        key=lambda item: item['created_at'],
        reverse=True,
    )[:10]
 
    context = {
        'total_scans': total_scans,
        'message_total': message_total,
        'url_total': url_total,
 
        'safe_count': safe_count,
        'suspicious_count': suspicious_count,
        'high_risk_count': high_risk_count,
 
        'safe_percentage': _percent(safe_count, total_scans),
        'suspicious_percentage': _percent(suspicious_count, total_scans),
        'high_risk_percentage': _percent(high_risk_count, total_scans),
        'message_percentage': _percent(message_total, total_scans),
        'url_percentage': _percent(url_total, total_scans),
 
        'week_total': week_total,
        'recent_history': recent_history,
 
        # Read by the charts' JavaScript via {{ chart_data|json_script }}
        'chart_data': {
            'levels': {'safe': safe_count, 'suspicious': suspicious_count, 'high': high_risk_count},
            'weekly': weekly_chart,
        },
    }
    return render(request, 'userapp/user_dashboard.html', context)
    

# -------------------------------------------------
# ADMIN DASHBOARD
# -------------------------------------------------

@login_required
def admin_dashboard(request):

    # -------------------------------------------------
    # ADMIN ACCESS
    # -------------------------------------------------
    if not _is_admin(request.user):
        messages.error(
            request,
            "You don't have permission to view the admin dashboard."
        )
        return redirect('user_dashboard')

    today = timezone.localdate()

    # -------------------------------------------------
    # REGISTERED USERS
    # -------------------------------------------------
    latest_users = User.objects.order_by('-date_joined')[:5]

    total_users = User.objects.count()

    # -------------------------------------------------
    # MESSAGE SCAN COUNTS
    # -------------------------------------------------
    message_total = ScanHistory.objects.count()

    legitimate_count = ScanHistory.objects.filter(
        result='Legitimate'
    ).count()

    spam_count = ScanHistory.objects.filter(
        result='Spam'
    ).count()

    phishing_count = ScanHistory.objects.filter(
        result='Scam / Phishing'
    ).count()

    # -------------------------------------------------
    # URL SCAN COUNTS
    # -------------------------------------------------
    url_total = URLScanHistory.objects.count()

    low_url_count = URLScanHistory.objects.filter(
        result='Low Risk'
    ).count()

    suspicious_url_count = URLScanHistory.objects.filter(
        result='Suspicious'
    ).count()

    high_url_count = URLScanHistory.objects.filter(
        result='High Risk'
    ).count()

    # -------------------------------------------------
    # OVERALL RISK COUNTS
    # -------------------------------------------------
    low_risk_count = legitimate_count + low_url_count

    medium_risk_count = spam_count + suspicious_url_count

    high_risk_count = phishing_count + high_url_count

    total_scans = message_total + url_total

    # -------------------------------------------------
    # DASHBOARD KPI CALCULATIONS
    # -------------------------------------------------

    # Detected scam and spam messages
    detected_message_count = spam_count + phishing_count

    # High-risk detections across both scanners
    high_risk_detections = phishing_count + high_url_count

    # Percentage of detected scam messages
    scam_percentage = (
        (detected_message_count / message_total) * 100
        if message_total else 0
    )

    # -------------------------------------------------
    # MONTH-OVER-MONTH COMPARISON
    # -------------------------------------------------

    current_month_start = today.replace(day=1)

    previous_month_end = current_month_start - timedelta(days=1)

    previous_month_start = previous_month_end.replace(day=1)

    # Current month message scans
    current_month_scans = ScanHistory.objects.filter(
        created_at__date__gte=current_month_start,
        created_at__date__lte=today
    ).count()

    # Previous month message scans
    previous_month_scans = ScanHistory.objects.filter(
        created_at__date__gte=previous_month_start,
        created_at__date__lte=previous_month_end
    ).count()

    if previous_month_scans:
        scan_change_percentage = (
            (current_month_scans - previous_month_scans)
            / previous_month_scans
        ) * 100
    else:
        scan_change_percentage = None

    # Current month high-risk detections
    current_month_high_risk = (
        ScanHistory.objects.filter(
            result='Scam / Phishing',
            created_at__date__gte=current_month_start,
            created_at__date__lte=today
        ).count()
        +
        URLScanHistory.objects.filter(
            result='High Risk',
            created_at__date__gte=current_month_start,
            created_at__date__lte=today
        ).count()
    )

    # Previous month high-risk detections
    previous_month_high_risk = (
        ScanHistory.objects.filter(
            result='Scam / Phishing',
            created_at__date__gte=previous_month_start,
            created_at__date__lte=previous_month_end
        ).count()
        +
        URLScanHistory.objects.filter(
            result='High Risk',
            created_at__date__gte=previous_month_start,
            created_at__date__lte=previous_month_end
        ).count()
    )

    if previous_month_high_risk:
        high_risk_change_percentage = (
            (current_month_high_risk - previous_month_high_risk)
            / previous_month_high_risk
        ) * 100
    else:
        high_risk_change_percentage = None

    
    # -------------------------------------------------
    # COMBINE MESSAGE AND URL SCANS
    # -------------------------------------------------
    combined_scans = []

    message_records = ScanHistory.objects.select_related(
        'user'
    ).order_by('-created_at')[:500]

    for scan in message_records:

        if scan.result == 'Legitimate':
            risk = 'Low'

        elif scan.result == 'Spam':
            risk = 'Medium'

        else:
            risk = 'High'

        combined_scans.append({
            'scan_id': f'M-{scan.id}',
            'user': scan.user.username,
            'content': scan.message,
            'channel': 'Message',
            'risk': risk,
            'category': scan.result,
            'scanned': timezone.localtime(
                scan.created_at
            ).strftime('%d %b %Y, %I:%M %p'),
            'timestamp': scan.created_at.timestamp(),
        })

    url_records = URLScanHistory.objects.select_related(
        'user'
    ).order_by('-created_at')[:500]

    for scan in url_records:

        if scan.result == 'Low Risk':
            risk = 'Low'

        elif scan.result == 'Suspicious':
            risk = 'Medium'

        else:
            risk = 'High'

        combined_scans.append({
            'scan_id': f'U-{scan.id}',
            'user': scan.user.username,
            'content': scan.url,
            'channel': 'URL',
            'risk': risk,
            'category': scan.result,
            'scanned': timezone.localtime(
                scan.created_at
            ).strftime('%d %b %Y, %I:%M %p'),
            'timestamp': scan.created_at.timestamp(),
        })

    # Latest scans first
    combined_scans.sort(
        key=lambda item: item['timestamp'],
        reverse=True
    )

    # -------------------------------------------------
    # DETECTED SCAM CATEGORY COUNTS
    # -------------------------------------------------
    category_counts = [
        {
            'name': 'Scam / Phishing',
            'count': phishing_count,
        },
        {
            'name': 'Spam',
            'count': spam_count,
        },
        {
            'name': 'High Risk URLs',
            'count': high_url_count,
        },
    ]

    # -------------------------------------------------
    # DAILY SCAN COUNTS - LAST 7 DAYS
    # -------------------------------------------------
    daily_trend = []

    for offset in range(6, -1, -1):

        current_day = today - timedelta(days=offset)

        message_day = ScanHistory.objects.filter(
            created_at__date=current_day
        )

        url_day = URLScanHistory.objects.filter(
            created_at__date=current_day
        )

        daily_trend.append({
            'date': current_day.strftime('%d %b'),

            'low': (
                message_day.filter(
                    result='Legitimate'
                ).count()
                +
                url_day.filter(
                    result='Low Risk'
                ).count()
            ),

            'medium': (
                message_day.filter(
                    result='Spam'
                ).count()
                +
                url_day.filter(
                    result='Suspicious'
                ).count()
            ),

            'high': (
                message_day.filter(
                    result='Scam / Phishing'
                ).count()
                +
                url_day.filter(
                    result='High Risk'
                ).count()
            ),
        })

    # -------------------------------------------------
    # RISK DISTRIBUTION
    # -------------------------------------------------
    risk_counts = {
        'low': low_risk_count,
        'medium': medium_risk_count,
        'high': high_risk_count,
        'total': total_scans,
    }

    # -------------------------------------------------
    # DASHBOARD CONTEXT
    # -------------------------------------------------
    context = {

        # Users
        'total_users': total_users,
        'latest_users': latest_users,

        # Overall scans
        'total_scans': total_scans,
        'message_total': message_total,
        'url_total': url_total,

        # Risk counts
        'low_risk_count': low_risk_count,
        'medium_risk_count': medium_risk_count,
        'high_risk_count': high_risk_count,

        # Message classifications
        'legitimate_count': legitimate_count,
        'spam_count': spam_count,
        'phishing_count': phishing_count,

        # URL classifications
        'low_url_count': low_url_count,
        'suspicious_url_count': suspicious_url_count,
        'high_url_count': high_url_count,

        # Dashboard KPI cards
        'detected_count': detected_message_count + high_url_count,
        'detected_message_count': detected_message_count,
        'high_risk_detections': high_risk_detections,
        'scam_percentage': round(scam_percentage, 1),

        # Monthly comparisons
        'scan_change_percentage': (
            round(scan_change_percentage, 1)
            if scan_change_percentage is not None else None
        ),

        'high_risk_change_percentage': (
            round(high_risk_change_percentage, 1)
            if high_risk_change_percentage is not None else None
        ),

       

        # Charts and scan activity
        'scan_data': combined_scans,
        'daily_trend': daily_trend,
        'category_counts': category_counts,
        'risk_counts': risk_counts,
    }

    return render(
        request,
        'adminapp/admin_dashboard.html',
        context
    )


# ---------------------------------------------------------------------------
# Logout
# ---------------------------------------------------------------------------

def user_logout(request):
    auth_logout(request)
    messages.success(request, "Logged out successfully.")
    return redirect('login')








    
# ---------------------------------------------------------------------------
# ADMIN
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# User Management
# ---------------------------------------------------------------------------

@login_required
def user_management(request):
    if not _is_admin(request.user):
        messages.error(request, "You don't have permission to manage users.")
        return redirect('user_dashboard')

    users = User.objects.order_by('-date_joined')

    context = {
        'users': users,
        'total_users': users.count(),
    }

    return render(request, 'adminapp/user_management.html', context)



@login_required
@require_POST
def toggle_user_status(request, user_id):

    if not _is_admin(request.user):
        messages.error(request, "You don't have permission to manage users.")
        return redirect('user_dashboard')

    user = get_object_or_404(User, pk=user_id)

    # Prevent changing your own account
    if user.pk == request.user.pk:
        messages.error(request, "You cannot deactivate your own account.")
        return redirect('user_management')

    # Protect superuser accounts
    if user.is_superuser:
        messages.error(request, "Superuser accounts cannot be modified here.")
        return redirect('user_management')

    user.is_active = not user.is_active
    user.save(update_fields=['is_active'])

    if user.is_active:
        messages.success(
            request,
            f"'{user.username}' has been activated successfully."
        )
    else:
        messages.success(
            request,
            f"'{user.username}' has been deactivated successfully."
        )

    return redirect('user_management')


# ------------------------------------------------------------------
# Message Scans
# ------------------------------------------------------------------

@admin_required
def admin_message_scans(request):

    scans = ScanHistory.objects.select_related('user').all()

    search = request.GET.get('search', '').strip()

    if search:
        scans = scans.filter(
            Q(message__icontains=search) |
            Q(result__icontains=search) |
            Q(user__username__icontains=search) |
            Q(user__email__icontains=search)
        )

    paginator = Paginator(scans, 10)
    page_number = request.GET.get('page')
    page_obj = paginator.get_page(page_number)

    context = {
        'page_obj': page_obj,
        'scans': page_obj,
        'search': search,
        'total_scans': ScanHistory.objects.count(),
    }

    return render(request, 'adminapp/message_scans.html', context)


# ------------------------------------------------------------------
# Detected Scams
# ------------------------------------------------------------------

@admin_required
def admin_detected_scams(request):

    message_scams = ScanHistory.objects.select_related('user').filter(
        result__in=['Scam / Phishing', 'Spam']
    )

    url_scams = URLScanHistory.objects.select_related('user').filter(
        result='High Risk'
    )

    message_search = request.GET.get('message_search', '').strip()
    url_search = request.GET.get('url_search', '').strip()

    if message_search:
        message_scams = message_scams.filter(
            Q(message__icontains=message_search) |
            Q(user__username__icontains=message_search)
        )

    if url_search:
        url_scams = url_scams.filter(
            Q(url__icontains=url_search) |
            Q(domain__icontains=url_search) |
            Q(user__username__icontains=url_search)
        )

    context = {
        'message_scams': message_scams,
        'url_scams': url_scams,
        'message_search': message_search,
        'url_search': url_search,
        'total_message_scams': message_scams.count(),
        'total_url_scams': url_scams.count(),
        'total_detected': message_scams.count() + url_scams.count(),
    }

    return render(request, 'adminapp/detected_scams.html', context)

# ------------------------------------------------------------------
# Risk Analysis
# ------------------------------------------------------------------

@admin_required
def admin_risk_analysis(request):

    # Message scan statistics
    message_total = ScanHistory.objects.count()

    legitimate_count = ScanHistory.objects.filter(
        result='Legitimate'
    ).count()

    phishing_count = ScanHistory.objects.filter(
        result='Scam / Phishing'
    ).count()

    spam_count = ScanHistory.objects.filter(
        result='Spam'
    ).count()

    # URL scan statistics
    url_total = URLScanHistory.objects.count()

    low_risk_count = URLScanHistory.objects.filter(
        result='Low Risk'
    ).count()

    suspicious_count = URLScanHistory.objects.filter(
        result='Suspicious'
    ).count()

    high_risk_count = URLScanHistory.objects.filter(
        result='High Risk'
    ).count()

    # Overall statistics
    total_scans = message_total + url_total

    detected_count = phishing_count + spam_count + high_risk_count

    context = {
        'total_scans': total_scans,
        'message_total': message_total,
        'url_total': url_total,

        'legitimate_count': legitimate_count,
        'phishing_count': phishing_count,
        'spam_count': spam_count,

        'low_risk_count': low_risk_count,
        'suspicious_count': suspicious_count,
        'high_risk_count': high_risk_count,

        'detected_count': detected_count,

        'message_chart_data': {
            'labels': ['Legitimate', 'Scam / Phishing', 'Spam'],
            'values': [
                legitimate_count,
                phishing_count,
                spam_count
            ],
        },

        'url_chart_data': {
            'labels': ['Low Risk', 'Suspicious', 'High Risk'],
            'values': [
                low_risk_count,
                suspicious_count,
                high_risk_count
            ],
        },

        'scanner_chart_data': {
            'labels': ['Message Scanner', 'URL Scanner'],
            'values': [message_total, url_total],
        },
    }

    return render(request, 'adminapp/risk_analysis.html', context)














# ---------------------------------------------------------------------------
#USESR
# ---------------------------------------------------------------------------

# ---------------------------------------------------------------------------
# Message Scanner
# ---------------------------------------------------------------------------

@login_required
def message_scanner(request):

    prediction = None

    if request.method == 'POST':

        message = request.POST.get('message', '').strip()

        if not message:
            messages.error(request, "Please enter a message to analyze.")

        elif len(message) > 10000:
            messages.error(request, "Message cannot exceed 10,000 characters.")

        else:
            try:
                # Get ML prediction
                prediction = predict_message(message)

                # Save analysis with logged-in user
                ScanHistory.objects.create(
                    user=request.user,
                    message=message,
                    result=prediction['result'],
                    confidence=prediction['confidence'],
                    probabilities=prediction['probabilities']
                )

            except FileNotFoundError:
                messages.error(request, "ML model file was not found.")

            except Exception:
                messages.error(
                    request,
                    "Unable to analyze the message. Please try again."
                )

        # Display the latest scan history for this user
    history = ScanHistory.objects.filter(
        user=request.user
    )[:10]

    context = {
        'prediction': prediction,
        'history': history,
    }

    return render(request, 'userapp/message_scanner.html', context)


@login_required
def scan_history(request):

    history = ScanHistory.objects.filter(
        user=request.user
    )

    context = {
        'history': history,
        'total_scans': history.count(),
        'scam_count': history.filter(
            result='Scam / Phishing'
        ).count(),
        'legitimate_count': history.filter(
            result='Legitimate'
        ).count(),
    }

    return render(
        request,
        'userapp/scan_history.html',
        context
    )


@login_required
def scan_detail(request, scan_id):

    scan = get_object_or_404(
        ScanHistory,
        id=scan_id,
        user=request.user
    )

    return render(
        request,
        'userapp/scan_detail.html',
        {'scan': scan}
    )





@login_required
def url_scanner(request):
    prediction = None

    if request.method == 'POST':
        url = request.POST.get('url', '').strip()

        try:
            if not url:
                raise ValueError("Please enter a URL.")

            prediction = scan_url(url)

            URLScanHistory.objects.create(
                user=request.user,
                url=prediction['url'],
                domain=prediction['domain'],
                risk_score=prediction['risk_score'],
                result=prediction['result'],
                reasons=prediction['reasons']
            )

        except ValueError as error:
            messages.error(request, str(error))

        except Exception:
            messages.error(
                request,
                "Unable to scan this URL. Please try again."
            )

    recent_scans = URLScanHistory.objects.filter(
        user=request.user
    )[:5]

    context = {
        'prediction': prediction,
        'recent_scans': recent_scans,
    }

    return render(
        request,
        'userapp/url_scanner.html',
        context
    )


@login_required
def url_scan_history(request):
    history = URLScanHistory.objects.filter(
        user=request.user
    )

    context = {
        'history': history,
        'total_scans': history.count(),
        'high_risk_count': history.filter(
            result='High Risk'
        ).count(),
        'suspicious_count': history.filter(
            result='Suspicious'
        ).count(),
        'low_risk_count': history.filter(
            result='Low Risk'
        ).count(),
    }

    return render(
        request,
        'userapp/url_scan_history.html',
        context
    )


@login_required
def url_scan_detail(request, scan_id):
    scan = get_object_or_404(
        URLScanHistory,
        id=scan_id,
        user=request.user
    )

    return render(
        request,
        'userapp/url_scan_detail.html',
        {'scan': scan}
    )


# ---------------------------------------------------------------------------
#  Manage Profile
# ---------------------------------------------------------------------------

@login_required
def user_profile(request):

    user = request.user

    if request.method == 'POST':

        full_name = request.POST.get('full_name', '').strip()
        email = request.POST.get('email', '').strip()
        phone = request.POST.get('phone', '').strip()
        address = request.POST.get('address', '').strip()

        if not full_name or not email:

            messages.error(
                request,
                "Full name and email are required."
            )

        elif User.objects.filter(
            email__iexact=email
        ).exclude(id=user.id).exists():

            messages.error(
                request,
                "This email address is already registered."
            )

        else:

            user.full_name = full_name
            user.email = email
            user.phone = phone or None
            user.address = address or None

            try:
                user.full_clean()
                user.save()

                messages.success(
                    request,
                    "Your profile has been updated successfully."
                )

                return redirect('user_profile')

            except ValidationError as error:

                if hasattr(error, 'message_dict'):
                    for field_errors in error.message_dict.values():
                        for error_message in field_errors:
                            messages.error(request, error_message)
                else:
                    for error_message in error.messages:
                        messages.error(request, error_message)

    return render(
        request,
        'userapp/user_profile.html',
        {'profile_user': user}
    )
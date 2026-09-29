from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Vulnerability, Technology


# ================= REGISTER =================

def register_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        email = request.POST.get("email")
        password = request.POST.get("password")
        confirm_password = request.POST.get("confirm_password")

        if password != confirm_password:
            messages.error(request, "Passwords do not match.")
            return redirect("register")

        if User.objects.filter(username=username).exists():
            messages.error(request, "Username already taken.")
            return redirect("register")

        if User.objects.filter(email=email).exists():
            messages.error(request, "Email already registered.")
            return redirect("register")

        user = User.objects.create_user(
            username=username,
            email=email,
            password=password
        )
        user.save()

        messages.success(
            request,
            "Account created successfully. Please login."
        )
        return redirect("login")

    return render(request, "accounts/register.html")


# ================= LOGIN =================

def login_view(request):
    if request.method == "POST":
        username = request.POST.get("username")
        password = request.POST.get("password")

        user = authenticate(
            request,
            username=username,
            password=password
        )

        if user is not None:
            auth_login(request, user)
            return redirect("dashboard")
        else:
            messages.error(
                request,
                "Invalid username or password."
            )
            return redirect("login")

    return render(request, "accounts/login.html")


# ================= DASHBOARD =================

@login_required(login_url="login")
def dashboard_view(request):
    return render(request, "accounts/dashboard.html")


# ================= LOGOUT =================

def logout_view(request):
    auth_logout(request)
    return redirect("login")


# ================= VULNERABILITIES =================

@login_required(login_url="login")
def vulnerabilities_view(request):

    # Get all vulnerabilities
    vulnerabilities = Vulnerability.objects.all()

    # ================= SEARCH =================

    search = request.GET.get("search", "").strip()

    if search:
        vulnerabilities = vulnerabilities.filter(
            cve_id__icontains=search
        )

    # ================= SEVERITY FILTER =================

    severity = request.GET.get("severity", "").strip().upper()

    if severity:
        vulnerabilities = vulnerabilities.filter(
            severity=severity
        )

    # Order by highest CVSS score first
    vulnerabilities = vulnerabilities.order_by("-cvss_score")

    # ================= TECHNOLOGY RELEVANCE =================

    # User ki saari technologies ka naam list mein lo
    user_technologies = Technology.objects.values_list(
        "name",
        flat=True
    )

    tech_names = [t.lower() for t in user_technologies]

    # Har CVE ke liye check karo relevant hai ya nahi
    for vuln in vulnerabilities:
        description_lower = vuln.description.lower()

        matched = [
            t for t in tech_names
            if t in description_lower
        ]

        vuln.is_relevant = len(matched) > 0
        vuln.matched_tech = (
            ", ".join(matched)
            if matched
            else None
        )

    return render(
        request,
        "accounts/vulnerabilities.html",
        {
            "vulnerabilities": vulnerabilities,
            "search": search,
            "selected_severity": severity,
        }
    )


# ================= TECHNOLOGY STACK =================

@login_required(login_url="login")
def technology_view(request):

    if request.method == "POST":

        name = request.POST.get(
            "name",
            ""
        ).strip()

        version = request.POST.get(
            "version",
            ""
        ).strip()

        description = request.POST.get(
            "description",
            ""
        ).strip()

        category = request.POST.get(
            "category",
            "os"
        ).strip()

        if name:

            Technology.objects.create(
                name=name,
                version=version,
                description=description,
                category=category
            )

            messages.success(
                request,
                "Technology added successfully."
            )

        return redirect("technology")

    technologies = Technology.objects.all().order_by(
        "category",
        "name"
    )

    grouped = {}

    for tech in technologies:
        grouped.setdefault(
            tech.category,
            []
        ).append(tech)

    return render(
        request,
        "accounts/technology.html",
        {
            "grouped": grouped,
        }
    )
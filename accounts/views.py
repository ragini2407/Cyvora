from django.shortcuts import render, redirect
from django.contrib.auth.models import User
from django.contrib.auth import authenticate, login as auth_login, logout as auth_logout
from django.contrib.auth.decorators import login_required
from django.contrib import messages
from .models import Vulnerability, Technology

from django.http import HttpResponse
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (
    SimpleDocTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)


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

    total = Vulnerability.objects.count()

    critical = Vulnerability.objects.filter(
        severity="CRITICAL"
    ).count()

    high = Vulnerability.objects.filter(
        severity="HIGH"
    ).count()

    medium = Vulnerability.objects.filter(
        severity="MEDIUM"
    ).count()

    low = Vulnerability.objects.filter(
        severity="LOW"
    ).count()

    return render(
        request,
        "accounts/dashboard.html",
        {
            "total": total,
            "critical": critical,
            "high": high,
            "medium": medium,
            "low": low,
        }
    )


# ================= LOGOUT =================

def logout_view(request):

    auth_logout(request)

    return redirect("login")


# ================= VULNERABILITIES =================

@login_required(login_url="login")
def vulnerabilities_view(request):

    vulnerabilities = Vulnerability.objects.all()

    # ================= SEARCH =================

    search = request.GET.get(
        "search",
        ""
    ).strip()

    if search:

        vulnerabilities = vulnerabilities.filter(
            cve_id__icontains=search
        )

    # ================= SEVERITY FILTER =================

    severity = request.GET.get(
        "severity",
        ""
    ).strip().upper()

    if severity:

        vulnerabilities = vulnerabilities.filter(
            severity=severity
        )

    # ================= TECHNOLOGY RELEVANCE =================

    user_technologies = Technology.objects.values_list(
        "name",
        flat=True
    )

    tech_names = [
        t.lower()
        for t in user_technologies
    ]

    # Calculate relevance and priority

    for vuln in vulnerabilities:

        description_lower = vuln.description.lower()

        matched = [
            t
            for t in tech_names
            if t in description_lower
        ]

        vuln.is_relevant = len(matched) > 0

        vuln.matched_tech = (
            ", ".join(matched)
            if matched
            else None
        )

        # ================= PRIORITY SCORE =================

        if vuln.cvss_score is not None:

            # Convert CVSS 0-10 into 0-100

            priority = vuln.cvss_score * 10

            # Technology relevance gets additional priority

            if vuln.is_relevant:
                priority += 10

            # Maximum score = 100

            vuln.priority_score = min(
                priority,
                100
            )

        else:

            vuln.priority_score = 0

    # Highest priority first

    vulnerabilities = sorted(
        vulnerabilities,
        key=lambda x: x.priority_score,
        reverse=True
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

    # ================= POST ACTIONS =================

    if request.method == "POST":

        action = request.POST.get("action", "add").strip()

        # ==================================================
        # ADD TECHNOLOGY
        # ==================================================

        if action == "add":

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
                    f"{name} added to your technology stack."
                )

            else:

                messages.error(
                    request,
                    "Technology name is required."
                )

            return redirect("technology")


        # ==================================================
        # EDIT TECHNOLOGY
        # ==================================================

        elif action == "edit":

            technology_id = request.POST.get(
                "technology_id"
            )

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

            try:

                technology = Technology.objects.get(
                    id=technology_id
                )

                if not name:

                    messages.error(
                        request,
                        "Technology name is required."
                    )

                    return redirect("technology")

                technology.name = name
                technology.version = version
                technology.description = description
                technology.category = category

                technology.save()

                messages.success(
                    request,
                    f"{name} updated successfully."
                )

            except Technology.DoesNotExist:

                messages.error(
                    request,
                    "Technology not found."
                )

            return redirect("technology")


        # ==================================================
        # DELETE TECHNOLOGY
        # ==================================================

        elif action == "delete":

            technology_id = request.POST.get(
                "technology_id"
            )

            try:

                technology = Technology.objects.get(
                    id=technology_id
                )

                technology_name = technology.name

                technology.delete()

                messages.success(
                    request,
                    f"{technology_name} removed from your technology stack."
                )

            except Technology.DoesNotExist:

                messages.error(
                    request,
                    "Technology not found."
                )

            return redirect("technology")


    # ================= GET TECHNOLOGIES =================

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


    # ================= TECHNOLOGY COUNTS =================

    context = {

        "grouped": grouped,

        "total_technologies": technologies.count(),

        "os_count": len(
            grouped.get("os", [])
        ),

        "web_count": len(
            grouped.get("web", [])
        ),

        "database_count": len(
            grouped.get("database", [])
        ),

        "language_count": len(
            grouped.get("language", [])
        ),

        "cloud_count": len(
            grouped.get("cloud", [])
        ),

        "security_count": len(
            grouped.get("security", [])
        ),
    }


    return render(
        request,
        "accounts/technology.html",
        context
    )

# ================= PDF REPORT =================

@login_required(login_url="login")
def generate_report_view(request):

    vulnerabilities = Vulnerability.objects.all().order_by(
        "-cvss_score"
    )

    response = HttpResponse(
        content_type="application/pdf"
    )

    response["Content-Disposition"] = (
        'attachment; '
        'filename="cyvora_vulnerability_report.pdf"'
    )

    doc = SimpleDocTemplate(
        response,
        pagesize=A4,
        rightMargin=15 * mm,
        leftMargin=15 * mm,
        topMargin=15 * mm,
        bottomMargin=15 * mm,
    )

    styles = getSampleStyleSheet()

    story = []

    # ================= TITLE =================

    title = Paragraph(
        "<b>CYVORA</b>",
        styles["Title"]
    )

    story.append(title)

    story.append(
        Paragraph(
            "AI Cybersecurity Intelligence & Vulnerability Prioritization Platform",
            styles["Normal"]
        )
    )

    story.append(
        Spacer(
            1,
            10
        )
    )

    # ================= STATISTICS =================

    total = vulnerabilities.count()

    critical = vulnerabilities.filter(
        severity="CRITICAL"
    ).count()

    high = vulnerabilities.filter(
        severity="HIGH"
    ).count()

    medium = vulnerabilities.filter(
        severity="MEDIUM"
    ).count()

    low = vulnerabilities.filter(
        severity="LOW"
    ).count()

    story.append(
        Paragraph(
            "<b>Vulnerability Overview</b>",
            styles["Heading2"]
        )
    )

    statistics = [
        [
            "Total",
            "Critical",
            "High",
            "Medium",
            "Low"
        ],
        [
            str(total),
            str(critical),
            str(high),
            str(medium),
            str(low)
        ],
    ]

    stats_table = Table(
        statistics,
        colWidths=[35 * mm] * 5
    )

    stats_table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#1f6feb")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "ALIGN",
                (0, 0),
                (-1, -1),
                "CENTER"
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "FONTNAME",
                (0, 1),
                (-1, 1),
                "Helvetica-Bold"
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.5,
                colors.grey
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                8
            ),
        ])
    )

    story.append(stats_table)

    story.append(
        Spacer(
            1,
            15
        )
    )

    # ================= VULNERABILITY TABLE =================

    story.append(
        Paragraph(
            "<b>Vulnerability Details</b>",
            styles["Heading2"]
        )
    )

    data = [
        [
            "CVE ID",
            "Severity",
            "CVSS",
            "Priority",
            "Relevance",
        ]
    ]

    technology_names = list(
        Technology.objects.values_list(
            "name",
            flat=True
        )
    )

    for vuln in vulnerabilities:

        # ================= RELEVANCE =================

        matched = [
            tech
            for tech in technology_names
            if tech.lower() in vuln.description.lower()
        ]

        relevance = (
            ", ".join(matched)
            if matched
            else "—"
        )

        # ================= PRIORITY =================

        if vuln.cvss_score is not None:

            priority = vuln.cvss_score * 10

            if matched:
                priority += 10

            priority = min(
                priority,
                100
            )

        else:

            priority = 0

        data.append([
            vuln.cve_id,
            vuln.severity or "—",
            str(vuln.cvss_score or "—"),
            f"{priority:.1f}",
            relevance,
        ])

    table = Table(
        data,
        repeatRows=1,
        colWidths=[
            35 * mm,
            25 * mm,
            20 * mm,
            25 * mm,
            65 * mm,
        ],
    )

    table.setStyle(
        TableStyle([
            (
                "BACKGROUND",
                (0, 0),
                (-1, 0),
                colors.HexColor("#1f6feb")
            ),
            (
                "TEXTCOLOR",
                (0, 0),
                (-1, 0),
                colors.white
            ),
            (
                "FONTNAME",
                (0, 0),
                (-1, 0),
                "Helvetica-Bold"
            ),
            (
                "GRID",
                (0, 0),
                (-1, -1),
                0.4,
                colors.grey
            ),
            (
                "VALIGN",
                (0, 0),
                (-1, -1),
                "TOP"
            ),
            (
                "FONTSIZE",
                (0, 0),
                (-1, -1),
                7
            ),
            (
                "TOPPADDING",
                (0, 0),
                (-1, -1),
                5
            ),
            (
                "BOTTOMPADDING",
                (0, 0),
                (-1, -1),
                5
            ),
        ])
    )

    story.append(table)

    doc.build(story)

    return response
from django.shortcuts import redirect
from django.urls import path

from . import views


def home_redirect(request):
    return redirect("login")


urlpatterns = [
    path("", home_redirect, name="home"),

    path("register/", views.register_view, name="register"),
    path("login/", views.login_view, name="login"),
    path("dashboard/", views.dashboard_view, name="dashboard"),
    path("logout/", views.logout_view, name="logout"),

    path(
        "vulnerabilities/",
        views.vulnerabilities_view,
        name="vulnerabilities"
    ),

    path(
        "technology/",
        views.technology_view,
        name="technology"
    ),
]
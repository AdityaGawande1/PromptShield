"""
URL configuration for PromptShield dashboard.
"""
from django.urls import path
from . import views

urlpatterns = [
    path("", views.index, name="index"),
    path("about/", views.about_view, name="about"),
    path("playground/", views.playground_view, name="playground"),
    path("run-tests/", views.run_tests_view, name="run_tests"),
    path("run-comparison/", views.run_comparison_view, name="run_comparison"),
    path("logs/", views.logs_view, name="logs"),
    path("metrics/", views.metrics_view, name="metrics"),
    path("metrics/json/", views.metrics_json, name="metrics_json"),
    path("clear-logs/", views.clear_logs_view, name="clear_logs"),
    path("init-db/", views.init_db_view, name="init_db"),
    path("api/incidents/", views.api_incidents, name="api_incidents"),
]

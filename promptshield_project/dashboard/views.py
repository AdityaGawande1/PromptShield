"""
Django views for PromptShield dashboard.
"""
import json
import subprocess
import sys
from pathlib import Path
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from django.views.decorators.csrf import csrf_exempt
from django.views.decorators.http import require_http_methods
from django.conf import settings

# Add project root to path for imports
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from logging_db.models import get_incidents, get_incident_count, clear_logs, init_db
from evaluation.test_runner import run_playground_prompt


def index(request):
    """Main dashboard page."""
    return render(request, "dashboard/index.html")


def about_view(request):
    """About page with project background and facts."""
    return render(request, "dashboard/about.html")


def playground_view(request):
    """Interactive page to test a custom, free-typed prompt against the pipeline."""
    result = None
    prompt_text = ""
    protection_enabled = True

    if request.method == "POST":
        prompt_text = request.POST.get("prompt_text", "").strip()
        protection_enabled = request.POST.get("protection") == "on"

        if prompt_text:
            incident = run_playground_prompt(prompt_text, protection_enabled)
            result = {
                "detector_verdict": incident.detector_verdict,
                "detector_confidence": incident.detector_confidence,
                "detector_signals": json.loads(incident.detector_signals) if incident.detector_signals else [],
                "target_response": incident.target_response,
                "output_guard_verdict": incident.output_guard_verdict,
                "output_guard_findings": json.loads(incident.output_guard_findings) if incident.output_guard_findings else [],
                "final_response": incident.final_response,
                "action_taken": incident.action_taken,
                "leakage_detected": incident.leakage_detected,
                "total_latency_ms": incident.total_latency_ms,
                "remediation_action": incident.remediation_action,
            }

    context = {
        "result": result,
        "prompt_text": prompt_text,
        "protection_enabled": protection_enabled,
    }
    return render(request, "dashboard/playground.html", context)


def run_tests_view(request):
    """Page to run test suite."""
    if request.method == "POST":
        protection = request.POST.get("protection") == "on"
        max_prompts = request.POST.get("max_prompts")
        max_prompts = int(max_prompts) if max_prompts else None
        clear = request.POST.get("clear") == "on"
        
        # Run in background or synchronously
        # For simplicity, run synchronously (could use Celery in production)
        from evaluation.test_runner import run_test_suite

        results = run_test_suite(
            protection_enabled=protection,
            clear_existing=clear,
            max_prompts=max_prompts
        )
        
        return JsonResponse({"success": True, "results": results})
    
    return render(request, "dashboard/run_tests.html")


def run_comparison_view(request):
    """Run comparison test (protection OFF vs ON)."""
    if request.method == "POST":
        max_prompts = request.POST.get("max_prompts")
        max_prompts = int(max_prompts) if max_prompts else None

        from evaluation.test_runner import run_comparison_test
        
        results = run_comparison_test(max_prompts=max_prompts)
        
        return JsonResponse({"success": True, "results": results})
    
    return render(request, "dashboard/run_comparison.html")


def logs_view(request):
    """View incident logs with filters."""
    # Get filter parameters
    category = request.GET.get("category", "")
    protection = request.GET.get("protection", "")
    expected_label = request.GET.get("expected_label", "")
    page = int(request.GET.get("page", 1))
    page_size = 50
    offset = (page - 1) * page_size
    
    # Convert protection filter
    protection_enabled = None
    if protection == "true":
        protection_enabled = True
    elif protection == "false":
        protection_enabled = False
    
    # Get incidents
    incidents = get_incidents(
        category=category if category else None,
        protection_enabled=protection_enabled,
        expected_label=expected_label if expected_label else None,
        limit=page_size,
        offset=offset
    )
    
    # Get total count for pagination
    total_count = get_incident_count(
        category=category if category else None,
        protection_enabled=protection_enabled,
        expected_label=expected_label if expected_label else None
    )
    
    # Get unique categories for filter dropdown
    all_incidents = get_incidents(limit=10000)
    categories = sorted(set(inc.category for inc in all_incidents))
    
    total_pages = (total_count + page_size - 1) // page_size
    
    # Generate page range for pagination
    if total_pages <= 7:
        page_range = list(range(1, total_pages + 1))
    else:
        if page <= 4:
            page_range = [1, 2, 3, 4, 5, '...', total_pages]
        elif page >= total_pages - 3:
            page_range = [1, '...', total_pages - 4, total_pages - 3, total_pages - 2, total_pages - 1, total_pages]
        else:
            page_range = [1, '...', page - 1, page, page + 1, '...', total_pages]
    
    context = {
        "incidents": incidents,
        "categories": categories,
        "current_category": category,
        "current_protection": protection,
        "current_expected_label": expected_label,
        "page": page,
        "page_size": page_size,
        "total_count": total_count,
        "total_pages": total_pages,
        "page_range": page_range,
    }
    
    return render(request, "dashboard/logs.html", context)


def metrics_view(request):
    """View evaluation metrics."""
    from evaluation.metrics import compute_all_metrics

    metrics = compute_all_metrics()
    
    context = {
        "metrics": metrics,
    }
    
    return render(request, "dashboard/metrics.html", context)


def metrics_json(request):
    """Return metrics as JSON."""
    from evaluation.metrics import compute_all_metrics

    metrics = compute_all_metrics()
    return JsonResponse(metrics)


def clear_logs_view(request):
    """Clear all incident logs."""
    if request.method == "POST":
        clear_logs()
        return redirect("logs")
    return JsonResponse({"success": False, "message": "POST required"}, status=405)


def init_db_view(request):
    """Initialize database."""
    if request.method == "POST":
        init_db()
        return JsonResponse({"success": True, "message": "Database initialized"})
    return JsonResponse({"success": False, "message": "POST required"}, status=405)


def api_incidents(request):
    """API endpoint for incidents (for charts)."""
    category = request.GET.get("category")
    protection = request.GET.get("protection")
    expected_label = request.GET.get("expected_label")
    
    protection_enabled = None
    if protection == "true":
        protection_enabled = True
    elif protection == "false":
        protection_enabled = False
    
    incidents = get_incidents(
        category=category,
        protection_enabled=protection_enabled,
        expected_label=expected_label,
        limit=1000
    )
    
    data = []
    for inc in incidents:
        data.append({
            "id": inc.id,
            "timestamp": inc.timestamp,
            "category": inc.category,
            "expected_label": inc.expected_label,
            "protection_enabled": inc.protection_enabled,
            "detector_verdict": inc.detector_verdict,
            "action_taken": inc.action_taken,
            "attack_success": inc.attack_success,
            "leakage_detected": inc.leakage_detected,
            "total_latency_ms": inc.total_latency_ms,
        })
    
    return JsonResponse({"incidents": data, "count": len(data)})

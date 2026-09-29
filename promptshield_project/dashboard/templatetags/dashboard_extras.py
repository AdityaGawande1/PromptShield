"""
Custom template filters for the PromptShield dashboard.
"""
from django import template

register = template.Library()


@register.filter
def percent(value, decimals=2):
    """Format a 0-1 fraction as a percentage number (without the % sign)."""
    try:
        return f"{float(value) * 100:.{int(decimals)}f}"
    except (TypeError, ValueError):
        return "0.00"


@register.filter
def sub(value, arg):
    """Subtract arg from value, returning a float. Used for per-category reduction."""
    try:
        return float(value) - float(arg)
    except (TypeError, ValueError):
        return 0.0


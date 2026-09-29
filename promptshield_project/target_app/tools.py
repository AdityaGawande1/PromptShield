"""
Fake tool for demonstrating tool misuse / excessive permissions.
This is a mock database query tool gated behind a permission check.
"""
import json
import re
from typing import Dict, Any
from pathlib import Path


# Mock database data
MOCK_DB = {
    "users": [
        {"id": 1, "name": "Alice", "email": "alice@example.com", "role": "admin"},
        {"id": 2, "name": "Bob", "email": "bob@example.com", "role": "user"},
        {"id": 3, "name": "Charlie", "email": "charlie@example.com", "role": "user"},
    ],
    "orders": [
        {"id": 101, "user_id": 1, "amount": 99.99, "status": "completed"},
        {"id": 102, "user_id": 2, "amount": 49.50, "status": "pending"},
        {"id": 103, "user_id": 3, "amount": 199.00, "status": "shipped"},
    ],
    "products": [
        {"id": 1, "name": "Widget A", "price": 29.99},
        {"id": 2, "name": "Widget B", "price": 49.99},
        {"id": 3, "name": "Widget C", "price": 19.99},
    ]
}


POLICY_PATH = Path(__file__).with_name("policy.json")


def load_policy() -> Dict[str, Any]:
    """Load the tool access policy from disk so role rules are data-driven."""
    with open(POLICY_PATH, "r") as f:
        return json.load(f)


def _role_policy(user_role: str) -> Dict[str, Any]:
    policy = load_policy()
    return policy.get("roles", {}).get(user_role, {})


def _extract_operation(query: str) -> str:
    match = re.match(r"\s*([A-Za-z]+)", query)
    return match.group(1).upper() if match else ""


def _extract_table(query: str) -> str:
    query_lower = query.lower()
    patterns = [
        r"\bfrom\s+([a-z_][a-z0-9_]*)",
        r"\binto\s+([a-z_][a-z0-9_]*)",
        r"\bupdate\s+([a-z_][a-z0-9_]*)",
        r"\btable\s+([a-z_][a-z0-9_]*)",
    ]
    for pattern in patterns:
        match = re.search(pattern, query_lower)
        if match:
            return match.group(1)
    for table in MOCK_DB:
        if table in query_lower:
            return table
    return ""


def check_permission(user_role: str, required_permission: str) -> bool:
    """
    Check if a user role has the required permission.

    Existing callers pass permission strings like read_users or delete_any; this
    function now resolves those names through target_app/policy.json.
    """
    role_policy = _role_policy(user_role)
    allowed_tables = set(role_policy.get("allowed_tables", []))
    denied_operations = set(role_policy.get("denied_operations", []))

    if required_permission.startswith("read_"):
        table = required_permission.removeprefix("read_")
        return table in allowed_tables

    if required_permission == "delete_any":
        return "DELETE" not in denied_operations

    if required_permission.startswith("write_"):
        table = required_permission.removeprefix("write_")
        write_denied = {"INSERT", "UPDATE", "DELETE"}.intersection(denied_operations)
        return table in allowed_tables and not write_denied

    return False


def run_db_query(query: str, user_role: str = "user") -> Dict[str, Any]:
    """
    Mock database query tool.
    
    Args:
        query: SQL-like query string (simplified)
        user_role: Role of the user making the request
    
    Returns:
        Dict with query results or error
    """
    query_lower = query.lower().strip()
    role_policy = _role_policy(user_role)
    if not role_policy:
        return {"success": False, "error": f"Unknown role: {user_role}", "data": None}

    operation = _extract_operation(query)
    table = _extract_table(query)
    denied_operations = set(role_policy.get("denied_operations", []))
    allowed_tables = set(role_policy.get("allowed_tables", []))

    if operation in denied_operations:
        return {
            "success": False,
            "error": f"Permission denied: '{operation}' operation is denied for role '{user_role}'",
            "data": None
        }

    if table and table not in allowed_tables:
        return {
            "success": False,
            "error": f"Permission denied: role '{user_role}' cannot access table '{table}'",
            "data": None
        }
    
    # Check for dangerous operations
    dangerous_keywords = ["drop", "delete", "truncate", "alter", "create", "insert", "update"]
    for kw in dangerous_keywords:
        if kw in query_lower:
            if kw.upper() in denied_operations:
                return {
                    "success": False,
                    "error": f"Permission denied: '{kw.upper()}' operation is denied for role '{user_role}'",
                    "data": None
                }
    
    # Simple query parsing for demo
    if "select * from users" in query_lower:
        if not check_permission(user_role, "read_users"):
            return {"success": False, "error": "Permission denied: read_users requires admin", "data": None}
        return {"success": True, "data": MOCK_DB["users"]}
    
    elif "select * from orders" in query_lower:
        if not check_permission(user_role, "read_orders"):
            return {"success": False, "error": "Permission denied: read_orders requires user or admin", "data": None}
        return {"success": True, "data": MOCK_DB["orders"]}
    
    elif "select * from products" in query_lower:
        if not check_permission(user_role, "read_products"):
            return {"success": False, "error": "Permission denied", "data": None}
        return {"success": True, "data": MOCK_DB["products"]}
    
    elif "select" in query_lower and "where" in query_lower:
        # Very basic WHERE clause support for demo
        if "users" in query_lower:
            if not check_permission(user_role, "read_users"):
                return {"success": False, "error": "Permission denied", "data": None}
            # Extract simple condition like "id = 1"
            return {"success": True, "data": MOCK_DB["users"][:1]}
    
    return {
        "success": False,
        "error": f"Unsupported query: {query}",
        "data": None
    }


# Tool schema for the LLM
TOOL_SCHEMA = {
    "name": "run_db_query",
    "description": "Execute a read-only SQL query on the mock database. Use for retrieving user, order, or product data.",
    "parameters": {
        "type": "object",
        "properties": {
            "query": {
                "type": "string",
                "description": "SQL SELECT query (e.g., 'SELECT * FROM users')"
            }
        },
        "required": ["query"]
    }
}

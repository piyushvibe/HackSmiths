"""Mock Secure Secret Vault for LLM-Shield.

Enterprise assets are stored securely in backend memory and never hardcoded in frontend.
Assets are never retrieved unless explicit RBAC and Step-Up MFA criteria are satisfied.
"""

from typing import Any, Dict, Optional, Tuple

_VAULT_STORE: Dict[str, Dict[str, Any]] = {
    "AWS_PRODUCTION_KEY": {
        "name": "Production AWS Secret Key",
        "sensitivity": "SECRET",
        "required_permission": "PRODUCTION_SECRET_READ",
        "data": (
            "AWS Production Credentials (Decrypted from Vault):\n"
            "• AWS_ACCESS_KEY_ID: AKIAIOSFODNN7EXAMPLE\n"
            "• AWS_SECRET_ACCESS_KEY: wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
            "• Region: us-east-1 (Production Primary)"
        ),
    },
    "DATABASE_PASSWORD": {
        "name": "Production Database Password",
        "sensitivity": "SECRET",
        "required_permission": "DB_SECRET_READ",
        "data": (
            "Production Database Cluster Access:\n"
            "• Host: prod-db-cluster.enterprise.internal:5432\n"
            "• Database: enterprise_core\n"
            "• Username: postgres_admin\n"
            "• Password: db_prod_super_secret_9981#!"
        ),
    },
    "JWT_SECRET": {
        "name": "Production JWT Secret Key",
        "sensitivity": "SECRET",
        "required_permission": "JWT_SECRET_READ",
        "data": (
            "Authentication JWT Signing Secret:\n"
            "• Key: jwt_hmac_secret_key_prod_89a3f7\n"
            "• Algorithm: HS256\n"
            "• Issuer: enterprise-auth.internal"
        ),
    },
    "INTERNAL_API_KEY": {
        "name": "Internal API Secret Key",
        "sensitivity": "SECRET",
        "required_permission": "SECRET_ACCESS",
        "data": (
            "Internal Microservice Mesh Secret:\n"
            "• Service: mesh-gateway-auth\n"
            "• API Key: internal-svc-key-88192\n"
            "• Scope: cluster:internal:rw"
        ),
    },
    "CUSTOMER_RECORDS": {
        "name": "Customer Rahul's Address & PII",
        "sensitivity": "CONFIDENTIAL",
        "required_permission": "CUSTOMER_PII_READ",
        "data": (
            "Customer Identity Record (Confidential CRM):\n"
            "• Customer ID: CUST-98124\n"
            "• Full Name: Rahul Sharma\n"
            "• Corporate Email: rahul.sharma@example.com\n"
            "• Residential Address: 42 Park Street, Bengaluru, Karnataka 560001\n"
            "• Phone: +91 9876543210\n"
            "• Status: Active Premium Customer"
        ),
    },
    "ADDRESS": {
        "name": "Customer Residential Address",
        "sensitivity": "CONFIDENTIAL",
        "required_permission": "ADDRESS_READ",
        "data": (
            "Customer Residential Address (Confidential CRM):\n"
            "• Customer: Rahul Sharma\n"
            "• Residential Address: 42 Park Street, Bengaluru, Karnataka 560001\n"
            "• Verification: Verified Primary Residence"
        ),
    },
    "PHONE_NUMBER": {
        "name": "Customer Phone Number",
        "sensitivity": "CONFIDENTIAL",
        "required_permission": "PHONE_READ",
        "data": (
            "Customer Phone Record (Confidential CRM):\n"
            "• Customer: Rahul Sharma\n"
            "• Mobile Phone: +91 9876543210\n"
            "• Verification: Primary Verified Mobile"
        ),
    },
    "INTERNAL_DEV_DOCS": {
        "name": "Internal Developer Documentation",
        "sensitivity": "INTERNAL",
        "required_permission": "INTERNAL_DOCS_READ",
        "data": (
            "Internal Engineering Guide:\n"
            "• Architecture: Microservices communicate via gRPC over Envoy service mesh.\n"
            "• Build Pipeline: GitHub Actions CI with automated SAST and container scans.\n"
            "• Logging: Structured JSON logs shipped to OpenSearch with DLP sanitization."
        ),
    },
    "COMPANY_PUBLIC_INFO": {
        "name": "Company Public Website & Overview",
        "sensitivity": "PUBLIC",
        "required_permission": "PUBLIC_READ",
        "data": (
            "LLM-Shield Enterprise AI Security Proxy:\n"
            "• Mission: Real-time defense-in-depth security proxy protecting enterprise LLM workflows.\n"
            "• Website: https://llm-shield.enterprise.ai\n"
            "• Compliance: SOC2 Type II, ISO 27001, GDPR, HIPAA ready."
        ),
    },
}


def retrieve_vault_asset(
    resource_id: str,
    role: str,
    mfa_verified: bool = False
) -> Tuple[bool, str, Optional[str]]:
    """Strictly controlled vault retrieval.
    
    Returns:
        Tuple[is_granted, reason, payload_string_or_none]
    """
    asset = _VAULT_STORE.get(resource_id)
    if not asset:
        return False, f"Unknown resource '{resource_id}'.", None

    sensitivity = asset["sensitivity"]

    # 1. Developer Role
    if role.strip().lower() == "developer":
        if sensitivity in ("SECRET", "CONFIDENTIAL"):
            return (
                False,
                f"Developer role does not have permission to access {sensitivity} resources ({asset['name']}).",
                None,
            )
        return True, "Developer authorized for internal/public resource.", asset["data"]

    # 2. Security Admin Role
    if role.strip().lower() == "security admin":
        if sensitivity == "SECRET" and not mfa_verified:
            return (
                False,
                f"Sensitive resource requested ({asset['name']}). Additional Step-Up MFA verification is required.",
                None,
            )
        return True, f"Security Admin authorized for {sensitivity} resource.", asset["data"]

    # 3. Any other role
    return False, f"Role '{role}' is not authorized to access '{asset['name']}'.", None

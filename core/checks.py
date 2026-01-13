from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Awaitable, Callable, Dict, List, Optional, Tuple

from core.graph_client import GraphClient

Status = str  # pass/fail/not_detected/error
Severity = str  # low/medium/high


@dataclass
class CheckOutput:
    check_key: str
    title: str
    category: str
    status: Status
    severity: Severity
    summary: str
    remediation: str
    evidence: Dict[str, Any]


async def _safe_list(gc: GraphClient, path: str, params: Optional[Dict[str, Any]] = None, limit: int = 50) -> List[Dict[str, Any]]:
    items: List[Dict[str, Any]] = []
    async for item in gc.get_paged(path, params=params):
        items.append(item)
        if len(items) >= limit:
            break
    return items


def _not_detected(check_key: str, title: str, category: str, why: str, fix: str) -> CheckOutput:
    return CheckOutput(
        check_key=check_key,
        title=title,
        category=category,
        status="not_detected",
        severity="medium",
        summary=why,
        remediation=fix,
        evidence={},
    )


async def check_tenant_info(gc: GraphClient) -> Tuple[Optional[str], Optional[str]]:
    try:
        org = await gc.get_json("/organization")
        val = (org.get("value") or [])
        if not val:
            return None, None
        return val[0].get("id"), val[0].get("displayName")
    except Exception:
        return None, None


async def ca_policies(gc: GraphClient) -> List[Dict[str, Any]]:
    return await _safe_list(gc, "/identity/conditionalAccess/policies", limit=200)


def _policy_grants_mfa(p: Dict[str, Any]) -> bool:
    grant = (p.get("grantControls") or {})
    controls = (grant.get("builtInControls") or [])
    return any(c.lower() == "mfa" for c in controls)


def _policy_blocks(p: Dict[str, Any]) -> bool:
    grant = (p.get("grantControls") or {})
    controls = (grant.get("builtInControls") or [])
    return any(c.lower() == "block" for c in controls)


def _targets_admin_roles(p: Dict[str, Any]) -> bool:
    # Best-effort heuristic. If includeRoles exists, it's often admin roles.
    users = ((p.get("conditions") or {}).get("users") or {})
    include_roles = users.get("includeRoles") or []
    return len(include_roles) > 0


def _targets_all_users(p: Dict[str, Any]) -> bool:
    users = ((p.get("conditions") or {}).get("users") or {})
    include_users = users.get("includeUsers") or []
    # "All" is commonly used.
    return any(u.lower() == "all" for u in include_users)


async def check_ca_mfa_admins(gc: GraphClient) -> CheckOutput:
    key = "ca_mfa_admins"
    title = "MFA required for admins (Conditional Access)"
    category = "Identity & Access"

    try:
        policies = await ca_policies(gc)
    except Exception as e:
        return _not_detected(
            key,
            title,
            category,
            f"Couldn't read Conditional Access policies ({e}). This often means the tenant doesn't have Entra ID P1/P2 or admin consent wasn't granted.",
            "If you have Entra ID P1/P2: create a Conditional Access policy that targets admin roles and requires MFA. Otherwise enable Security Defaults or per-user MFA.",
        )

    matching = [p for p in policies if _targets_admin_roles(p) and _policy_grants_mfa(p) and (p.get("state") == "enabled")]
    if matching:
        return CheckOutput(
            check_key=key,
            title=title,
            category=category,
            status="pass",
            severity="high",
            summary=f"Found {len(matching)} enabled Conditional Access policy/policies that target roles and require MFA.",
            remediation="Keep this policy enabled and review the targeted roles and exclusions regularly.",
            evidence={"policySamples": [{"id": p.get("id"), "displayName": p.get("displayName"), "state": p.get("state")} for p in matching[:5]]},
        )

    return CheckOutput(
        check_key=key,
        title=title,
        category=category,
        status="fail",
        severity="high",
        summary="No enabled Conditional Access policy found that clearly targets admin roles and requires MFA.",
        remediation="Create an enabled Conditional Access policy: Users -> include admin roles (or a privileged admin group), Cloud apps -> All apps, Grant -> Require MFA. Keep exclusions minimal.",
        evidence={"policiesChecked": len(policies)},
    )


async def check_ca_mfa_all_users(gc: GraphClient) -> CheckOutput:
    key = "ca_mfa_all_users"
    title = "MFA required for all users (Conditional Access)"
    category = "Identity & Access"

    try:
        policies = await ca_policies(gc)
    except Exception as e:
        return _not_detected(
            key,
            title,
            category,
            f"Couldn't read Conditional Access policies ({e}).",
            "If you have Entra ID P1/P2: create a Conditional Access policy requiring MFA for all users. Otherwise enable Security Defaults or per-user MFA.",
        )

    matching = [p for p in policies if _targets_all_users(p) and _policy_grants_mfa(p) and (p.get("state") == "enabled")]
    if matching:
        return CheckOutput(
            check_key=key,
            title=title,
            category=category,
            status="pass",
            severity="high",
            summary=f"Found {len(matching)} enabled policy/policies that include all users and require MFA.",
            remediation="Review exclusions (break-glass accounts) and ensure all cloud apps are covered.",
            evidence={"policySamples": [{"id": p.get("id"), "displayName": p.get("displayName"), "state": p.get("state")} for p in matching[:5]]},
        )

    return CheckOutput(
        check_key=key,
        title=title,
        category=category,
        status="fail",
        severity="high",
        summary="No enabled Conditional Access policy found that clearly includes all users and requires MFA.",
        remediation="Create an enabled Conditional Access policy: Users -> All users, Cloud apps -> All apps, Grant -> Require MFA. Add a break-glass admin account exclusion.",
        evidence={"policiesChecked": len(policies)},
    )


async def check_block_legacy_auth(gc: GraphClient) -> CheckOutput:
    key = "block_legacy_auth"
    title = "Legacy authentication blocked"
    category = "Identity & Access"

    try:
        policies = await ca_policies(gc)
    except Exception:
        return _not_detected(
            key,
            title,
            category,
            "Couldn't evaluate Conditional Access policies for legacy auth blocking.",
            "If possible, create a Conditional Access policy that blocks legacy authentication clients (often 'Other clients' / legacy protocols).",
        )

    # Heuristic: a policy that blocks and mentions legacy/other client types.
    matches = []
    for p in policies:
        if p.get("state") != "enabled":
            continue
        if not _policy_blocks(p):
            continue
        cond = p.get("conditions") or {}
        client_types = cond.get("clientAppTypes") or []
        name = (p.get("displayName") or "").lower()
        if any(ct.lower() == "other" for ct in client_types) or ("legacy" in name):
            matches.append(p)

    if matches:
        return CheckOutput(
            check_key=key,
            title=title,
            category=category,
            status="pass",
            severity="high",
            summary=f"Found {len(matches)} enabled policy/policies that appear to block legacy authentication.",
            remediation="Keep legacy auth blocked; monitor sign-in logs for remaining legacy clients and migrate them.",
            evidence={"policySamples": [{"id": p.get("id"), "displayName": p.get("displayName")} for p in matches[:5]]},
        )

    return CheckOutput(
        check_key=key,
        title=title,
        category=category,
        status="fail",
        severity="high",
        summary="No clear Conditional Access policy found that blocks legacy authentication.",
        remediation="Create an enabled Conditional Access policy that blocks legacy authentication clients (often 'Other clients') for all users. Then remediate any apps that still require legacy protocols.",
        evidence={"policiesChecked": len(policies)},
    )


async def check_privileged_role_assignments(gc: GraphClient) -> CheckOutput:
    key = "privileged_role_assignments"
    title = "Privileged role assignments inventory"
    category = "Identity & Access"

    try:
        assignments = await _safe_list(gc, "/roleManagement/directory/roleAssignments", limit=200)
    except Exception as e:
        return _not_detected(
            key,
            title,
            category,
            f"Couldn't read role assignments ({e}).",
            "Grant admin consent for RoleManagement.Read.Directory (delegated) and retry.",
        )

    # Count + sample
    count = len(assignments)
    severity = "high" if count > 10 else "medium"
    status = "pass" if count <= 10 else "fail"

    return CheckOutput(
        check_key=key,
        title=title,
        category=category,
        status=status,
        severity=severity,
        summary=f"Found {count} directory role assignment(s). More than ~10 often indicates overly broad admin access for an SMB.",
        remediation="Reduce privileged role assignments. Prefer just-in-time admin (PIM) if available, and keep Global Admins to the minimum needed.",
        evidence={"assignmentCount": count, "samples": assignments[:10]},
    )


async def check_directory_roles(gc: GraphClient) -> CheckOutput:
    key = "directory_roles"
    title = "Directory roles and memberships"
    category = "Identity & Access"

    try:
        roles = await _safe_list(gc, "/directoryRoles", limit=200)
    except Exception as e:
        return _not_detected(key, title, category, f"Couldn't list directory roles ({e}).", "Grant Directory.Read.All and retry.")

    # Sample members count for first few roles
    role_summaries = []
    for r in roles[:10]:
        rid = r.get("id")
        name = r.get("displayName")
        members = []
        try:
            members = await _safe_list(gc, f"/directoryRoles/{rid}/members", limit=50)
        except Exception:
            pass
        role_summaries.append({"id": rid, "displayName": name, "memberSampleCount": len(members)})

    return CheckOutput(
        check_key=key,
        title=title,
        category=category,
        status="pass",
        severity="low",
        summary=f"Found {len(roles)} role(s). Sampled membership counts for the first {len(role_summaries)} roles.",
        remediation="Review privileged roles (Global Admin, Privileged Role Admin, etc.) and ensure MFA is enforced for those users.",
        evidence={"roleCount": len(roles), "roleSamples": role_summaries},
    )


async def check_mfa_registration_coverage(gc: GraphClient) -> CheckOutput:
    key = "mfa_registration_coverage"
    title = "MFA registration coverage"
    category = "Identity & Access"

    try:
        rows = await _safe_list(gc, "/reports/authenticationMethods/userRegistrationDetails", limit=999)
    except Exception as e:
        return _not_detected(
            key,
            title,
            category,
            f"Couldn't read MFA registration report ({e}).",
            "Grant admin consent for Reports-related permissions if needed, or use Security Defaults/per-user MFA review as a fallback.",
        )

    total = len(rows)
    not_registered = [r for r in rows if not r.get("isMfaRegistered")]
    pct = 0.0 if total == 0 else (100.0 * (total - len(not_registered)) / total)

    status = "pass" if pct >= 95.0 else "fail"
    severity = "high" if pct < 80.0 else ("medium" if pct < 95.0 else "low")

    return CheckOutput(
        check_key=key,
        title=title,
        category=category,
        status=status,
        severity=severity,
        summary=f"MFA registered for ~{pct:.1f}% of users (based on available registration report).",
        remediation="Ensure all users register MFA methods. Start with admins and high-risk users. Consider enforcing registration with Conditional Access / Security Defaults.",
        evidence={"totalUsers": total, "notRegisteredSample": not_registered[:25]},
    )


async def check_per_user_auth_methods_sample(gc: GraphClient) -> CheckOutput:
    key = "per_user_auth_methods"
    title = "Per-user authentication methods (sample)"
    category = "Identity & Access"

    try:
        users = await _safe_list(gc, "/users", params={"$select": "id,displayName,userPrincipalName", "$top": "25"}, limit=25)
    except Exception as e:
        return _not_detected(key, title, category, f"Couldn't list users ({e}).", "Grant Directory.Read.All and retry.")

    samples = []
    for u in users[:10]:
        uid = u.get("id")
        try:
            methods = await _safe_list(gc, f"/users/{uid}/authentication/methods", limit=50)
            samples.append({"user": u.get("userPrincipalName"), "methodTypes": [m.get("@odata.type") for m in methods]})
        except Exception:
            continue

    return CheckOutput(
        check_key=key,
        title=title,
        category=category,
        status="pass" if samples else "not_detected",
        severity="low",
        summary="Collected authentication method types for a small sample of users.",
        remediation="Use this to spot-check that admins have strong MFA methods registered (Authenticator / FIDO2).",
        evidence={"samples": samples},
    )


async def check_signin_logs_sample(gc: GraphClient) -> CheckOutput:
    key = "signin_logs"
    title = "Sign-in logs accessible (sample)"
    category = "Logging & Monitoring"

    try:
        logs = await _safe_list(gc, "/auditLogs/signIns", params={"$top": "50"}, limit=50)
    except Exception as e:
        return _not_detected(
            key,
            title,
            category,
            f"Couldn't read sign-in logs ({e}).",
            "Grant admin consent for AuditLog.Read.All and ensure the signed-in user has a role that can read sign-in logs.",
        )

    failures = [l for l in logs if (l.get("status") or {}).get("errorCode") not in (0, "0", None)]

    return CheckOutput(
        check_key=key,
        title=title,
        category=category,
        status="pass",
        severity="low",
        summary=f"Retrieved {len(logs)} recent sign-in log entries (sample). Found {len(failures)} failures in the sample.",
        remediation="Review sign-in failures for brute force attempts and legacy clients. Consider alerting or conditional access hardening.",
        evidence={"sample": logs[:10]},
    )


async def check_directory_audit_logs_sample(gc: GraphClient) -> CheckOutput:
    key = "directory_audit_logs"
    title = "Directory audit logs accessible (sample)"
    category = "Logging & Monitoring"

    try:
        logs = await _safe_list(gc, "/auditLogs/directoryAudits", params={"$top": "50"}, limit=50)
    except Exception as e:
        return _not_detected(
            key,
            title,
            category,
            f"Couldn't read directory audit logs ({e}).",
            "Grant admin consent for AuditLog.Read.All and ensure the signed-in user can read directory audit logs.",
        )

    return CheckOutput(
        check_key=key,
        title=title,
        category=category,
        status="pass",
        severity="low",
        summary=f"Retrieved {len(logs)} directory audit log entries (sample).",
        remediation="Audit logs should be reviewed for admin changes (role assignments, app consent, etc.).",
        evidence={"sample": logs[:10]},
    )


async def check_applied_ca_policies_visibility(gc: GraphClient) -> CheckOutput:
    key = "applied_ca_policies_visibility"
    title = "Applied Conditional Access policies visible in sign-in logs"
    category = "Logging & Monitoring"

    try:
        logs = await _safe_list(gc, "/auditLogs/signIns", params={"$top": "10"}, limit=10)
    except Exception as e:
        return _not_detected(key, title, category, f"Couldn't read sign-in logs ({e}).", "Grant AuditLog.Read.All and retry.")

    has_field = any("appliedConditionalAccessPolicies" in l for l in logs)
    if has_field:
        return CheckOutput(
            check_key=key,
            title=title,
            category=category,
            status="pass",
            severity="low",
            summary="Sign-in logs include appliedConditionalAccessPolicies (policy evaluation visibility is available).",
            remediation="Keep Policy permissions and appropriate Entra roles for whoever runs scans.",
            evidence={"sample": [{"id": l.get("id"), "appliedCount": len(l.get("appliedConditionalAccessPolicies") or [])} for l in logs[:5]]},
        )

    return CheckOutput(
        check_key=key,
        title=title,
        category=category,
        status="not_detected",
        severity="medium",
        summary="Sign-in logs did not include appliedConditionalAccessPolicies in the sample. This can happen if the signed-in user/app lacks permission to read Conditional Access data.",
        remediation="Ensure the app has Policy.Read.All (delegated) and the signed-in user has an Entra role that can read Conditional Access data.",
        evidence={"sampleIds": [l.get("id") for l in logs if l.get("id")][:5]},
    )


async def check_tenant_licensing(gc: GraphClient) -> CheckOutput:
    key = "tenant_licensing"
    title = "Tenant licensing (subscribed SKUs explain feature availability)"
    category = "General"

    try:
        skus = await _safe_list(gc, "/subscribedSkus", limit=200)
    except Exception as e:
        return _not_detected(key, title, category, f"Couldn't read subscribed SKUs ({e}).", "Grant Organization.Read.All and retry.")

    # Create a short readable list
    sku_names = []
    for s in skus[:50]:
        part = s.get("skuPartNumber")
        if part:
            sku_names.append(part)

    return CheckOutput(
        check_key=key,
        title=title,
        category=category,
        status="pass",
        severity="low",
        summary=f"Found {len(skus)} subscribed SKU(s).",
        remediation="Use these SKUs to explain why some controls (like Conditional Access) may or may not be available.",
        evidence={"skuPartNumbers": sku_names},
    )


ALL_CHECKS: List[Callable[[GraphClient], Awaitable[CheckOutput]]] = [
    check_ca_mfa_admins,
    check_ca_mfa_all_users,
    check_block_legacy_auth,
    check_privileged_role_assignments,
    check_directory_roles,
    check_mfa_registration_coverage,
    check_per_user_auth_methods_sample,
    check_signin_logs_sample,
    check_directory_audit_logs_sample,
    check_applied_ca_policies_visibility,
    check_tenant_licensing,
]

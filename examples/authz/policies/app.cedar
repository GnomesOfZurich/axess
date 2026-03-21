// ── RBAC: role-based permissions ──────────────────────────────────────────────

// Admins can do anything.
permit (
    principal in DocApp::Role::"admin",
    action,
    resource is DocApp::Document
);

// Editors can view and edit documents.
permit (
    principal in DocApp::Role::"editor",
    action == DocApp::Action::"ViewDocument",
    resource is DocApp::Document
);

permit (
    principal in DocApp::Role::"editor",
    action == DocApp::Action::"EditDocument",
    resource is DocApp::Document
);

// Viewers can only view documents.
permit (
    principal in DocApp::Role::"viewer",
    action == DocApp::Action::"ViewDocument",
    resource is DocApp::Document
);

// ── ReBAC: ownership-based access ────────────────────────────────────────────

// Document owners can always view and edit their own documents.
permit (
    principal is DocApp::User,
    action == DocApp::Action::"ViewDocument",
    resource is DocApp::Document
) when {
    resource.owner == principal
};

permit (
    principal is DocApp::User,
    action == DocApp::Action::"EditDocument",
    resource is DocApp::Document
) when {
    resource.owner == principal
};

// ── ABAC: attribute-based conditions ─────────────────────────────────────────

// Delete requires MFA verification (even for admins, this is enforced via a
// separate policy that forbids delete without MFA context).
forbid (
    principal,
    action == DocApp::Action::"DeleteDocument",
    resource is DocApp::Document
) when {
    !context.mfa_verified
};

//! Whether a policy set reads the request context, decided from Cedar's
//! syntax tree of each policy and template.

use cedar_policy::pst::{Clause, Expr, Template, Var};
use cedar_policy::{PolicyId, PolicySet};

/// Whether any policy or template of `policies` reads the `context` variable.
///
/// The answer comes from Cedar's policy syntax tree ([`cedar_policy::pst`]),
/// so the word in a comment, a string, an attribute name, an entity id or an
/// annotation is not a read, and a read is found wherever an expression can
/// hold one. A scope cannot name `context`, so the `when` and `unless`
/// clauses are every place to look. A template counts whether or not a
/// policy is linked to it.
///
/// A policy Cedar cannot give a syntax tree for counts as a read, with a
/// warning that names it: the gate then asks for a context provider instead
/// of deciding on an empty context.
pub(super) fn reads_context(policies: &PolicySet) -> bool {
    let in_a_policy = policies.policies().any(|policy| match policy.to_pst() {
        Ok(tree) => body_reads_context(tree.body()),
        Err(error) => unreadable(policy.id(), &error),
    });
    in_a_policy
        || policies
            .templates()
            .any(|template| match template.to_pst() {
                Ok(tree) => body_reads_context(&tree),
                Err(error) => unreadable(template.id(), &error),
            })
}

/// Whether a `when` or `unless` clause of `body` reads `context`.
fn body_reads_context(body: &Template) -> bool {
    body.clauses().iter().any(|clause| match clause {
        Clause::When(condition) | Clause::Unless(condition) => expr_reads_context(condition),
    })
}

/// Whether `expr` holds the `context` variable at any depth, by Cedar's own
/// fold over the expression.
fn expr_reads_context(expr: &Expr) -> bool {
    expr.reduce(
        &|node| matches!(node, Expr::Var(Var::Context)).then_some(true),
        &|left, right| left || right,
        false,
    )
}

/// Logs that `id` has no syntax tree and answers that it reads `context`.
fn unreadable(id: &PolicyId, error: &dyn std::fmt::Display) -> bool {
    tracing::warn!(
        policy = %id,
        %error,
        "Cedar gave no syntax tree for a policy; it counts as reading `context`"
    );
    true
}

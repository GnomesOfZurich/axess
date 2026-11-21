// Approving a payment takes a FIDO2 assertion that verified the user (a PIN
// or a biometric, not only a touch) within the last five minutes.
//
// The annotation names the step-up that yields such an assertion: the
// passkey ceremony, which requires user verification. A session that falls
// short is answered `step_up_required` with that name, and nothing else of
// this policy.
@step_up("passkey")
permit (
    principal,
    action == Bank::Action::"ApprovePayment",
    resource
)
when {
    context.assurance has fido2 &&
    context.assurance.fido2.user_verified &&
    context.assurance.fido2.age_seconds <= 300
};

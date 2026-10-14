# OPA/Gatekeeper Rego Policies for SentinelCloud-Advanced
# These are enforced as validating admission webhooks via Gatekeeper

# -------------------------------------------------------------------
# Policy 1: Deny egress to port 445 in patient-vitals namespace
# -------------------------------------------------------------------
package kubernetes.admission.deny_smb_egress

violation[{"msg": msg}] {
    input.review.kind.kind == "CiliumNetworkPolicy"
    input.review.object.metadata.namespace == "medical"

    # Check if any egress rule allows port 445
    egress := input.review.object.spec.egress[_]
    port := egress.toPorts[_].ports[_]
    port.port == "445"

    # Exclude billing app
    not input.review.object.spec.endpointSelector.matchLabels.app == "billing"

    msg := sprintf(
        "Port 445 (SMB) egress is forbidden in namespace '%s' for non-billing workloads. Policy: %s",
        [input.review.object.metadata.namespace, input.review.object.metadata.name]
    )
}

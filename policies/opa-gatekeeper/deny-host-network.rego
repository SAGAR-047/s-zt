# OPA/Gatekeeper Rego Policy
# Deny hostNetwork: true in medical namespaces

package kubernetes.admission.deny_host_network

violation[{"msg": msg}] {
    input.review.kind.kind == "Pod"
    ns := input.review.object.metadata.namespace
    ns == "medical"

    input.review.object.spec.hostNetwork == true

    msg := sprintf(
        "hostNetwork is forbidden in namespace '%s'. Pod: %s",
        [ns, input.review.object.metadata.name]
    )
}

# Also check Deployments that create pods with hostNetwork
violation[{"msg": msg}] {
    input.review.kind.kind == "Deployment"
    ns := input.review.object.metadata.namespace
    ns == "medical"

    input.review.object.spec.template.spec.hostNetwork == true

    msg := sprintf(
        "hostNetwork is forbidden in namespace '%s'. Deployment: %s",
        [ns, input.review.object.metadata.name]
    )
}

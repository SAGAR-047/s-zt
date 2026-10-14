# OPA/Gatekeeper Rego Policy
# Deny ingress from external (0.0.0.0/0) except via Ingress controller

package kubernetes.admission.deny_external_ingress

violation[{"msg": msg}] {
    input.review.kind.kind == "CiliumNetworkPolicy"
    ns := input.review.object.metadata.namespace
    ns == "medical"

    ingress := input.review.object.spec.ingress[_]
    cidr := ingress.fromCIDR[_]
    cidr == "0.0.0.0/0"

    # Allow only if endpoint selector targets ingress-controller
    not input.review.object.spec.endpointSelector.matchLabels["app.kubernetes.io/name"] == "ingress-nginx"

    msg := sprintf(
        "External ingress (0.0.0.0/0) is forbidden in namespace '%s' except via Ingress controller. Policy: %s",
        [ns, input.review.object.metadata.name]
    )
}

#!/bin/bash
# ============================================================================
# SentinelCloud-Advanced: Infrastructure Setup Script
# ============================================================================
# This script sets up the complete K3s infrastructure for SentinelCloud.
# Run on the control-plane node (or locally with multipass/minikube).
#
# Prerequisites:
#   - Ubuntu 22.04 LTS
#   - Minimum 4 CPU, 8GB RAM per node
#   - Helm v3+ installed
#   - kubectl configured
#
# Usage:
#   chmod +x setup-infrastructure.sh
#   ./setup-infrastructure.sh
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$(dirname "$SCRIPT_DIR")")"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

log_info()  { echo -e "${GREEN}[INFO]${NC} $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC} $1"; }
log_error() { echo -e "${RED}[ERROR]${NC} $1"; }
log_step()  { echo -e "\n${BLUE}══════════════════════════════════════════════════${NC}"; echo -e "${BLUE}  $1${NC}"; echo -e "${BLUE}══════════════════════════════════════════════════${NC}"; }

# ============================================================================
# Step 1: Install K3s (if not already installed)
# ============================================================================
install_k3s() {
    log_step "Step 1: Installing K3s"

    if command -v k3s &> /dev/null; then
        log_info "K3s already installed: $(k3s --version)"
        return
    fi

    log_info "Installing K3s without default CNI (Cilium will be the CNI)..."
    curl -sfL https://get.k3s.io | INSTALL_K3S_EXEC="--flannel-backend=none --disable-network-policy --disable=traefik" sh -

    # Wait for K3s to be ready
    log_info "Waiting for K3s to be ready..."
    sleep 10
    sudo k3s kubectl wait --for=condition=Ready nodes --all --timeout=120s || true

    # Setup kubeconfig
    mkdir -p ~/.kube
    sudo cp /etc/rancher/k3s/k3s.yaml ~/.kube/config
    sudo chown "$(id -u):$(id -g)" ~/.kube/config
    export KUBECONFIG=~/.kube/config

    log_info "K3s installed successfully"
}

# ============================================================================
# Step 2: Install Helm (if not already installed)
# ============================================================================
install_helm() {
    log_step "Step 2: Installing Helm"

    if command -v helm &> /dev/null; then
        log_info "Helm already installed: $(helm version --short)"
        return
    fi

    curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    log_info "Helm installed: $(helm version --short)"
}

# ============================================================================
# Step 3: Install Cilium
# ============================================================================
install_cilium() {
    log_step "Step 3: Installing Cilium CNI (v1.15+)"

    helm repo add cilium https://helm.cilium.io/ || true
    helm repo update

    helm upgrade --install cilium cilium/cilium \
        --namespace kube-system \
        --set cluster.name=sentinel \
        --set operator.replicas=1 \
        --set ipam.mode=kubernetes \
        --set policyEnforcementMode=always \
        --set hubble.enabled=true \
        --set hubble.relay.enabled=true \
        --set hubble.ui.enabled=true \
        --wait --timeout 5m

    log_info "Waiting for Cilium to be ready..."
    kubectl -n kube-system wait --for=condition=Ready pods -l app.kubernetes.io/name=cilium-agent --timeout=120s
    log_info "Cilium installed and healthy"
}

# ============================================================================
# Step 4: Install Tetragon
# ============================================================================
install_tetragon() {
    log_step "Step 4: Installing Tetragon (eBPF observability)"

    helm upgrade --install tetragon cilium/tetragon \
        --namespace kube-system \
        --set tetragon.enabled=true \
        --wait --timeout 3m

    log_info "Tetragon installed"
}

# ============================================================================
# Step 5: Install Falco
# ============================================================================
install_falco() {
    log_step "Step 5: Installing Falco (runtime security)"

    helm repo add falcosecurity https://falcosecurity.github.io/charts || true
    helm repo update

    helm upgrade --install falco falcosecurity/falco \
        --namespace falco --create-namespace \
        --set ebpf.enabled=true \
        --set falcosidekick.enabled=false \
        --wait --timeout 5m

    log_info "Falco installed"
}

# ============================================================================
# Step 6: Install Gatekeeper (OPA)
# ============================================================================
install_gatekeeper() {
    log_step "Step 6: Installing OPA Gatekeeper"

    helm repo add gatekeeper https://open-policy-agent.github.io/gatekeeper/charts || true
    helm repo update

    helm upgrade --install gatekeeper gatekeeper/gatekeeper \
        --namespace gatekeeper-system --create-namespace \
        --set replicas=1 \
        --wait --timeout 3m

    log_info "Gatekeeper installed"

    # Apply constraint templates
    log_info "Applying Gatekeeper constraints..."
    kubectl apply -f "${PROJECT_ROOT}/policies/opa-gatekeeper/constraints.yaml" || log_warn "Constraint apply failed (may need Gatekeeper to be fully ready)"
}

# ============================================================================
# Step 7: Install Kafka (Strimzi)
# ============================================================================
install_kafka() {
    log_step "Step 7: Installing Kafka (Strimzi Operator)"

    kubectl create namespace sentinel 2>/dev/null || true

    kubectl create -f 'https://strimzi.io/install/latest?namespace=sentinel' -n sentinel 2>/dev/null || true

    # Wait for Strimzi operator
    sleep 15
    kubectl -n sentinel wait --for=condition=Ready pods -l name=strimzi-cluster-operator --timeout=120s 2>/dev/null || true

    # Create Kafka cluster
    cat <<EOF | kubectl apply -f -
apiVersion: kafka.strimzi.io/v1beta2
kind: Kafka
metadata:
  name: kafka
  namespace: sentinel
spec:
  kafka:
    version: 3.7.0
    replicas: 1
    listeners:
      - name: plain
        port: 9092
        type: internal
        tls: false
    storage:
      type: ephemeral
    config:
      offsets.topic.replication.factor: 1
      transaction.state.log.replication.factor: 1
      transaction.state.log.min.isr: 1
  zookeeper:
    replicas: 1
    storage:
      type: ephemeral
EOF

    log_info "Kafka cluster created (waiting for readiness...)"
    sleep 30

    # Create topics
    for topic in syscalls falco_alerts dns_blocks; do
        cat <<EOF | kubectl apply -f -
apiVersion: kafka.strimzi.io/v1beta2
kind: KafkaTopic
metadata:
  name: ${topic}
  namespace: sentinel
  labels:
    strimzi.io/cluster: kafka
spec:
  partitions: 3
  replicas: 1
EOF
    done

    log_info "Kafka topics created"
}

# ============================================================================
# Step 8: Install ClickHouse
# ============================================================================
install_clickhouse() {
    log_step "Step 8: Installing ClickHouse"

    # Install ClickHouse operator
    kubectl apply -f https://raw.githubusercontent.com/Altinity/clickhouse-operator/master/deploy/operator/clickhouse-operator-install-bundle.yaml 2>/dev/null || true

    sleep 10

    # Create ClickHouse instance
    cat <<EOF | kubectl apply -f -
apiVersion: clickhouse.altinity.com/v1
kind: ClickHouseInstallation
metadata:
  name: clickhouse
  namespace: sentinel
spec:
  configuration:
    clusters:
      - name: sentinel
        layout:
          shardsCount: 1
          replicasCount: 1
    users:
      default/networks/ip: "::/0"
  defaults:
    templates:
      dataVolumeClaimTemplate: data-volume
  templates:
    volumeClaimTemplates:
      - name: data-volume
        spec:
          accessModes:
            - ReadWriteOnce
          resources:
            requests:
              storage: 10Gi
EOF

    log_info "ClickHouse installed"
}

# ============================================================================
# Step 9: Deploy SecurityAlert CRD
# ============================================================================
install_crd() {
    log_step "Step 9: Installing SecurityAlert CRD"
    kubectl apply -f "${PROJECT_ROOT}/deploy/manifests/securityalert-crd.yaml"
    log_info "SecurityAlert CRD installed"
}

# ============================================================================
# Step 10: Deploy Cilium Network Policies
# ============================================================================
install_network_policies() {
    log_step "Step 10: Applying Cilium Network Policies"
    kubectl create namespace medical 2>/dev/null || true
    kubectl apply -f "${PROJECT_ROOT}/policies/cilium/baseline-policies.yaml"
    log_info "Cilium network policies applied"
}

# ============================================================================
# Main
# ============================================================================
main() {
    echo -e "\n${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  SentinelCloud-Advanced Infrastructure Setup          ║${NC}"
    echo -e "${GREEN}║  eBPF-Driven Autonomous Cyber-Resilience              ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}\n"

    install_k3s
    install_helm
    install_cilium
    install_tetragon
    install_falco
    install_gatekeeper
    install_kafka
    install_clickhouse
    install_crd
    install_network_policies

    echo -e "\n${GREEN}╔════════════════════════════════════════════════════════╗${NC}"
    echo -e "${GREEN}║  Infrastructure setup complete!                        ║${NC}"
    echo -e "${GREEN}║                                                        ║${NC}"
    echo -e "${GREEN}║  Next steps:                                           ║${NC}"
    echo -e "${GREEN}║  1. Build & push Docker images                         ║${NC}"
    echo -e "${GREEN}║  2. helm install sentinel ./deploy/sentinel-chart      ║${NC}"
    echo -e "${GREEN}║  3. Run the attack simulation                          ║${NC}"
    echo -e "${GREEN}╚════════════════════════════════════════════════════════╝${NC}\n"
}

main "$@"

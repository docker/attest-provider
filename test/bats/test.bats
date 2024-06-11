#!/usr/bin/env bats

load helpers

WAIT_TIME=120
SLEEP_TIME=1
GATEKEEPER_NAMESPACE=${GATEKEEPER_NAMESPACE:-gatekeeper-system}

teardown_file() {
  kubectl delete -f validation/
  #kubectl delete -f mutation/
}

@test "gatekeeper-controller-manager is running" {
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl -n ${GATEKEEPER_NAMESPACE} wait --for=condition=Ready --timeout=60s pod -l control-plane=controller-manager"
}

@test "gatekeeper-audit is running" {
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl -n ${GATEKEEPER_NAMESPACE} wait --for=condition=Ready --timeout=60s pod -l control-plane=audit-controller"
}

@test "attest-provider is running" {
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "kubectl -n ${GATEKEEPER_NAMESPACE} wait --for=condition=Ready --timeout=60s pod -l run=attest-provider"
  sleep 5 # we need a readiness probe https://kubernetes.io/docs/tasks/configure-pod-container/configure-liveness-readiness-startup-probes/#define-readiness-probes
}

@test "attest validation" {
  run kubectl apply -f validation/attest-constraint-template.yaml
  assert_success
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "constraint_enforced constrainttemplate k8sattestexternaldata"

  run kubectl apply -f validation/attest-constraint.yaml
  assert_success
  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "constraint_enforced k8sattestexternaldata deny-images-that-fail-policy"

  run kubectl create ns test
  run kubectl run nginx --image=nginx -n test --dry-run=server
  # should deny pod admission if the image doesn't pass policy
  assert_failure
  assert_match 'admit: false' "${output}"
}

# TODO: write mutating webhook policy
#@test "attest mutation" {
#  run kubectl apply -f mutation/external-data-provider-mutation.yaml
#  assert_success
#  wait_for_process ${WAIT_TIME} ${SLEEP_TIME} "mutator_enforced Assign append-valid-suffix-to-image"
#
#  run kubectl run nginx --image=nginx --dry-run=server --output json
#  assert_success
#  # should mutate the image field by appending "_valid" suffix
#  assert_match "nginx_valid" "$(jq -r '.spec.containers[0].image' <<< ${output})"
#}

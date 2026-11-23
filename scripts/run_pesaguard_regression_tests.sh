#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
API_REPO="${PESAGUARD_API_REPO:-$ROOT_DIR/../api.pesaguard}"
REPORT="$ROOT_DIR/reports/pesaguard-security-tests.xml"

if [[ "${PESAGUARD_SECURITY_TESTS_APPROVED:-}" != "YES" ]]; then
  echo "Refusing to execute PesaGuard tests without explicit approval."
  echo "Review docs/PESAGUARD-INTEGRATION.md, then set PESAGUARD_SECURITY_TESTS_APPROVED=YES."
  exit 2
fi

if [[ ! -e "$API_REPO/.git" ]]; then
  echo "PESAGUARD_API_REPO must point to a local PesaGuard API Git checkout."
  exit 2
fi

TEST_DIR="$API_REPO/pesaguard_backend_pipeline/tests"
REQUIRED_TESTS=(
  test_auth_lifecycle.py
  test_rbac_enforcement.py
  test_tenant_scope_constraints.py
  test_api_idempotency_contract.py
  test_daraja_validation.py
  test_daraja_tenant_routing.py
  test_export_tenant_scoping.py
  test_session_lifecycle_fail_closed.py
  test_transaction_routes.py
  test_data_protection.py
  test_etl_pipeline.py
  test_lineage.py
  test_mpesa_configuration.py
  test_mpesa_operations.py
  test_webhook_manager.py
)

for test_file in "${REQUIRED_TESTS[@]}"; do
  if [[ ! -f "$TEST_DIR/$test_file" ]]; then
    echo "Required regression test is missing: $TEST_DIR/$test_file"
    exit 2
  fi
done

mkdir -p "$ROOT_DIR/reports"

# Strip deployment credentials inherited from the shell before loading application
# modules. The PesaGuard conftest creates a temporary SQLite database and overrides
# DATABASE_URL. PostgreSQL race tests are deliberately not selected or enabled.
while IFS= read -r variable; do
  case "$variable" in
    *SECRET*|*TOKEN*|*PASSWORD*|*PASSKEY*|*API_KEY*|*CONSUMER_KEY*|*ACCESS_KEY*|*DATABASE_URL*|PYTEST_TEST_DB_URL|TEST_DATABASE_URL|REDIS_URL|KAFKA_BOOTSTRAP_SERVERS)
      unset "$variable"
      ;;
  esac
done < <(compgen -e)

export USE_IN_MEMORY_TEST_DB=1
export PESAGUARD_ENV=testing
export PESAGUARD_ENVIRONMENT=testing
export JWT_SECRET_KEY="pg-assess-isolated-test-key-only-not-for-deployment"
unset PESAGUARD_RUN_POSTGRES_INTEGRATION
unset PESAGUARD_POSTGRES_TEST_URL
unset PG_ASSESS_DATABASE_URL
unset PYTEST_ADDOPTS

ARGS=()
for test_file in "${REQUIRED_TESTS[@]}"; do
  ARGS+=("$TEST_DIR/$test_file")
done

cd "$API_REPO"
set +e
pytest -q "${ARGS[@]}" --junitxml="$REPORT"
STATUS=$?
set -e

echo "JUnit report: $REPORT"
echo "Pytest exit status: $STATUS"
exit "$STATUS"

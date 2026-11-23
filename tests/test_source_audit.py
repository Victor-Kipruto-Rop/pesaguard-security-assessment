from pg_assess.source_audit import audit_source_tree

def test_source_audit_is_non_executing_and_reports_missing_ledger(tmp_path):
    root = tmp_path / "checkout"
    package = root / "pesaguard_backend_pipeline"
    package.mkdir(parents=True)
    (package / "auth_rbac.py").write_text(
        'ACCESS_TOKEN_TTL_MINUTES <= 15\n"tenant_id"\nRefreshTokenRecord\n_hash_refresh_token\nabsolute_expires_at\n',
        encoding="utf-8")
    (package / "authorization_policy.py").write_text(
        "deny by default wildcard_rejected unknown_permission", encoding="utf-8")
    (package / "transaction_routes.py").write_text(
        "requested_tenant != authenticated_tenant tenant_access_denied Transaction.tenant_id == tenant_id",
        encoding="utf-8")
    (package / "models.py").write_text(
        'UniqueConstraint("tenant_id" CheckConstraint("tenant_id IS NOT NULL uq_transaction_scope_trans_id uq_idempotency_request uq_processed_scope_trans_id',
        encoding="utf-8")
    (package / "daraja_tenant_routing.py").write_text(
        'UnknownDarajaShortcode AmbiguousDarajaShortcode PaymentProvider.status == "active" MpesaIntegration.environment == environment',
        encoding="utf-8")
    (package / "event_store.py").write_text(
        "with_for_update() ProcessResult.DUPLICATE ProcessResult.CONFLICT IntegrityError", encoding="utf-8")
    (package / "mpesa_operation_service.py").write_text(
        '_CALLBACK_TOKEN hmac.compare_digest callback_token_digest callback_payload_digest correlation.state != "PENDING"',
        encoding="utf-8")
    (package / "mpesa_operation_webhooks.py").write_text(
        'request.args.get("token")', encoding="utf-8")
    (package / "validators.py").write_text("validate_daraja_payload", encoding="utf-8")
    (package / "mpesa_configuration.py").write_text(
        "AESGCM MPESA_CREDENTIALS_ENCRYPTION_KEY", encoding="utf-8")
    (package / "data_protection.py").write_text("protect_payload", encoding="utf-8")
    (package / "etl_pipeline.py").write_text("tenant_id=dataset.tenant_id", encoding="utf-8")
    (package / "lineage.py").write_text("tenant_id", encoding="utf-8")
    tests = package / "tests"
    tests.mkdir()
    for name in ["test_auth_lifecycle.py", "test_tenant_scope_constraints.py",
                 "test_daraja_validation.py", "test_postgres_concurrency.py"]:
        (tests / name).write_text("# synthetic test fixture", encoding="utf-8")

    report, risk = audit_source_tree(root)
    assert "identity" in report.checks_run
    assert any(f.check == "ledger" for f in report.findings)
    assert risk["finding_count"] == len(report.findings)

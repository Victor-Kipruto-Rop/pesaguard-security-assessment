from pg_assess.domain_checks import (
    daraja_checks, identity_checks, ledger_checks, tenancy_checks, transaction_checks,
    infrastructure_checks, outbound_webhook_checks, database_checks, pipeline_checks,
)

def test_tenant_cross_boundary_grant_is_critical():
    findings = tenancy_checks([{"case_id":"tenant-b-reads-a", "expected_allowed":False, "observed_allowed":True}])
    assert findings[0].severity == "critical"

def test_idempotency_multiple_effects_is_critical():
    findings = transaction_checks([{"case_id":"dup", "idempotency_key":"key",
        "response_fingerprint":"a", "side_effect_count":2}])
    assert any(f.severity == "critical" for f in findings)

def test_same_receipt_cannot_map_to_two_transactions():
    findings = transaction_checks([
        {"idempotency_key":"a","provider_receipt":"RCP1","transaction_id":"t1"},
        {"idempotency_key":"b","provider_receipt":"RCP1","transaction_id":"t2"},
    ])
    assert any("receipt" in f.title.lower() and f.severity == "critical" for f in findings)

def test_unbalanced_ledger_is_critical():
    findings = ledger_checks([
        {"transaction_id":"tx1","side":"debit","amount":"100.00"},
        {"transaction_id":"tx1","side":"credit","amount":"90.00"},
    ])
    assert any("balanced" in f.title.lower() and f.severity == "critical" for f in findings)

def test_posted_entry_mutability_is_critical():
    findings = ledger_checks([
        {"transaction_id":"tx1","side":"debit","amount":"10","status":"posted","mutable_after_posting":True},
        {"transaction_id":"tx1","side":"credit","amount":"10","status":"posted"},
    ])
    assert any("mutable" in f.title.lower() for f in findings)

def test_daraja_does_not_claim_inbound_hmac_by_default():
    findings = daraja_checks({"assumes_safaricom_hmac_signature":True}, [])
    assert any("HMAC assumption" in f.title for f in findings)

def test_hardcoded_secret_is_detected_without_recording_value():
    findings = infrastructure_checks([{"path":"compose.yml","content":"DARAJA_CONSUMER_SECRET: 'super-secret-value-123'"}])
    assert any("secret" in f.title.lower() for f in findings)
    assert all("super-secret-value-123" not in str(f.evidence) for f in findings)

def test_identity_controls_missing_are_reported():
    assert len(identity_checks({})) >= 8

def test_database_missing_tls_is_reported():
    assert any("tls" in f.title.lower() for f in database_checks({"sslmode":"disable"}))

def test_pipeline_secret_detection_does_not_echo_secret():
    findings = pipeline_checks({}, [{"path":"settings.py","content":"API_KEY = 'abcdefghijklmno-secret'"}])
    assert any("secret" in f.title.lower() for f in findings)
    assert all("abcdefghijklmno-secret" not in str(f.evidence) for f in findings)

def test_downstream_webhook_requires_signing_and_replay_window():
    titles = [f.title for f in outbound_webhook_checks({})]
    assert any("signing" in title.lower() for title in titles)
    assert any("replay" in title.lower() for title in titles)


def test_ledger_does_not_net_different_currencies():
    findings = ledger_checks([
        {"transaction_id":"fx-tx","side":"debit","amount":"100","currency":"KES"},
        {"transaction_id":"fx-tx","side":"credit","amount":"100","currency":"USD"},
    ])
    assert len([f for f in findings if "balanced" in f.title.lower()]) == 2


def test_idempotency_keys_are_scoped_by_tenant():
    findings = transaction_checks([
        {"tenant_id":"tenant-a","idempotency_key":"same-key","response_fingerprint":"result-a"},
        {"tenant_id":"tenant-b","idempotency_key":"same-key","response_fingerprint":"result-b"},
    ])
    assert not any("inconsistent outcomes" in f.title.lower() for f in findings)

def test_ledger_transaction_ids_are_scoped_by_tenant():
    findings = ledger_checks([
        {"tenant_id":"tenant-a","transaction_id":"shared-id","side":"debit","amount":"10","currency":"KES"},
        {"tenant_id":"tenant-b","transaction_id":"shared-id","side":"credit","amount":"10","currency":"KES"},
    ])
    assert len([f for f in findings if "balanced" in f.title.lower()]) == 2


def test_infrastructure_checks_flag_privileged_root_and_mutable_image():
    findings = infrastructure_checks([{
        "path":"deployment.yaml",
        "content":"privileged: true\nrunAsUser: 0\nrunAsNonRoot: false\nimage: api:latest\n"
    }])
    titles = [f.title for f in findings]
    assert any("privileged" in title.lower() for title in titles)
    assert any("root" in title.lower() for title in titles)
    assert any("latest" in title.lower() for title in titles)


def test_daraja_inbound_callback_does_not_require_undocumented_hmac():
    config = {
        "callback_url_secret_enabled":True,
        "callback_token_digest_stored":True,
        "constant_time_token_comparison":True,
        "terminal_callback_payload_digest":True,
        "pending_request_only":True,
        "provider_source_restrictions_verified":True,
        "correlate_to_initiated_request":True,
        "validate_amount_and_shortcode":True,
        "deduplicate_provider_receipt":True,
        "independent_status_reconciliation":True,
        "callback_payload_size_limited":True,
        "assumes_safaricom_hmac_signature":False,
    }
    findings = daraja_checks(config)
    assert not any("HMAC assumption" in f.title for f in findings)
    assert not any("signature" in f.title.lower() for f in findings)

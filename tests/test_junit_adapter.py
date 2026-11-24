import pytest
from pg_assess.junit_adapter import import_junit

def test_import_junit_maps_tenant_failure_to_critical(tmp_path):
    report_file = tmp_path / "results.xml"
    report_file.write_text(
        '<testsuite tests="2" failures="1" skipped="1">'
        '<testcase classname="tests.test_tenant_scope" name="test_cross_tenant_read"><failure message="secret output"/></testcase>'
        '<testcase classname="tests.test_auth" name="test_refresh_rotation"><skipped/></testcase>'
        '</testsuite>', encoding="utf-8")
    report, risk = import_junit(report_file)
    assert risk["test_counts"] == {"passed":0,"failed":1,"errors":0,"skipped":1}
    assert report.findings[0].severity == "critical"
    assert "secret output" not in str(report.model_dump())

def test_junit_rejects_doctype_and_entities(tmp_path):
    report_file = tmp_path / "bad.xml"
    report_file.write_text('<!DOCTYPE foo [<!ENTITY x "boom">]><testsuite><testcase name="x"/></testsuite>')
    with pytest.raises(ValueError, match="DTD"):
        import_junit(report_file)

def test_junit_rejects_empty_suite(tmp_path):
    report_file = tmp_path / "empty.xml"
    report_file.write_text("<testsuite/>")
    with pytest.raises(ValueError, match="no testcase"):
        import_junit(report_file)

def test_junit_tracks_domain_specific_execution_counts(tmp_path):
    report_file = tmp_path / "domain-results.xml"
    report_file.write_text(
        '<testsuite tests="3" failures="1">'
        '<testcase classname="tests.test_database_privileges" name="test_runtime_role"/>'
        '<testcase classname="tests.test_ledger_invariants" name="test_unbalanced_journal"><failure/></testcase>'
        '<testcase classname="tests.test_deployment_security" name="test_root_container"/>'
        '</testsuite>', encoding="utf-8")
    report, risk = import_junit(report_file)
    assert risk["domain_test_counts"]["database"]["passed"] == 1
    assert risk["domain_test_counts"]["ledger"]["failed"] == 1
    assert risk["domain_test_counts"]["infrastructure"]["passed"] == 1
    assert report.findings[0].check == "ledger"

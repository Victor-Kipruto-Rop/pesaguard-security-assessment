from pg_assess.evidence import EvidenceStore

def test_hash_chain_verifies_and_detects_tampering(tmp_path):
    path = tmp_path / "evidence.sqlite3"
    store = EvidenceStore(path)
    store.append("assessment.started", {"id":"a"})
    store.append("assessment.completed", {"id":"a","score":10})
    assert store.verify() == {"valid":True,"verified_events":2}
    import sqlite3
    with sqlite3.connect(path) as db:
        db.execute("UPDATE evidence SET payload_json='{}' WHERE sequence=1")
    assert store.verify()["valid"] is False

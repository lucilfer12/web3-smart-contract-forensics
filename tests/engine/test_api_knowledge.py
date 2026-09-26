from pathlib import Path
import asyncio

import httpx

from scf_engine.api import create_app
from scf_engine.engine import analyze
from scf_engine.knowledge import KnowledgeStore

ROOT = Path(__file__).parents[2]
VULN = ROOT / "fixtures" / "contracts" / "vulnerable"


def test_api_health_and_source_analysis():
    async def exercise():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            health = await client.get("/health")
            assert health.json()["status"] == "ok"
            response = await client.post("/analyze/source", json={
                "filename": "Api.sol",
                "source": "pragma solidity ^0.8.20; contract C { address public target; function x() external { target.delegatecall(\"\"); } }",
            })
            assert response.status_code == 200
            assert any(item["rule_id"] == "SCF-UPGRADE-001" for item in response.json()["findings"])
    asyncio.run(exercise())


def test_knowledge_store_round_trip(tmp_path):
    result = analyze(str(VULN))
    store = KnowledgeStore(str(tmp_path / "scf.db"))
    store.ingest(result)
    stats = store.stats()
    assert stats["sources"] == 1
    assert stats["entities"] >= 10
    assert stats["relationships"] >= 20
    assert any(item["rule_id"] == "SCF-TAINT-001" for item in store.findings())
    graph = store.graph()
    assert graph["nodes"]
    assert graph["edges"]
    store.close()


def test_api_knowledge_endpoints(tmp_path):
    db = str(tmp_path / "scf.db")
    store = KnowledgeStore(db)
    store.ingest(analyze(str(VULN)))
    store.close()

    async def exercise():
        transport = httpx.ASGITransport(app=create_app())
        async with httpx.AsyncClient(transport=transport, base_url="http://test") as client:
            stats = await client.get("/knowledge/stats", params={"db": db})
            assert stats.json()["findings"] >= 1
            findings = await client.get("/knowledge/findings", params={"severity": "Critical", "db": db})
            assert findings.status_code == 200
            graph = await client.get("/knowledge/graph", params={"db": db})
            assert graph.json()["nodes"]
    asyncio.run(exercise())

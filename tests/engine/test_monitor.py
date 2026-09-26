from scf_engine.monitor import scan_block, scan_blocks


class FakeRpc:
    def block(self, tag):
        return {"transactions": [{"hash": "0xtx", "from": "0xaaa", "to": "0xbbb"}, {"hash": "0xother", "from": "0xccc", "to": "0xddd"}]}


def test_scan_block_filters_watched_addresses():
    events = scan_block(FakeRpc(), 42, {"0xbbb"})
    assert len(events) == 1
    assert events[0].tx_hash == "0xtx"
    assert events[0].kind == "watched-transaction"


def test_scan_blocks_is_deterministic():
    events = scan_blocks(FakeRpc(), 1, 2, {"0xaaa"})
    assert [item.block_number for item in events] == ["0x1", "0x2"]

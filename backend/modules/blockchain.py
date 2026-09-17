"""
modules/blockchain.py — Simulated SHA-256 Proof-of-Work blockchain

3-node distributed architecture:
  Node-A detects an attack → mines a block → broadcasts to Node-B and Node-C
  Each receiving node verifies the hash chain before appending

No external dependencies — pure Python hashlib.
"""

import hashlib
import json
import time
import sys
import os
from datetime import datetime, timezone
from typing import List, Optional
from dataclasses import dataclass, asdict, field

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))
import config


# ─── Block ────────────────────────────────────────────────────────────────────

@dataclass
class Block:
    index: int
    timestamp: str
    attack_record: dict
    previous_hash: str
    nonce: int = 0
    hash: str = ""
    node: str = "node-A"

    def compute_hash(self) -> str:
        content = json.dumps({
            "index":         self.index,
            "timestamp":     self.timestamp,
            "attack_record": self.attack_record,
            "previous_hash": self.previous_hash,
            "nonce":         self.nonce,
            "node":          self.node,
        }, sort_keys=True)
        return hashlib.sha256(content.encode()).hexdigest()

    def mine(self, difficulty: int = 2) -> str:
        """Proof-of-Work: find a nonce so hash starts with `difficulty` zeros."""
        prefix = "0" * difficulty
        self.nonce = 0
        self.hash = self.compute_hash()
        while not self.hash.startswith(prefix):
            self.nonce += 1
            self.hash = self.compute_hash()
        return self.hash

    def to_dict(self) -> dict:
        return asdict(self)


# ─── Single-node chain ────────────────────────────────────────────────────────

class NodeChain:
    """One security node's local copy of the blockchain."""

    def __init__(self, node_id: str, difficulty: int = 2):
        self.node_id = node_id
        self.difficulty = difficulty
        self.chain: List[Block] = []
        self._add_genesis()

    def _add_genesis(self):
        genesis = Block(
            index=0,
            timestamp=datetime.now(timezone.utc).isoformat(),
            attack_record={"type": "genesis", "message": "DDoS Detection System — Genesis Block"},
            previous_hash="0" * 64,
            node=self.node_id,
        )
        genesis.hash = genesis.compute_hash()
        self.chain.append(genesis)

    @property
    def last_block(self) -> Block:
        return self.chain[-1]

    def add_block(self, attack_record: dict, mine: bool = True) -> Block:
        block = Block(
            index=len(self.chain),
            timestamp=datetime.now(timezone.utc).isoformat(),
            attack_record=attack_record,
            previous_hash=self.last_block.hash,
            node=self.node_id,
        )
        if mine:
            block.mine(self.difficulty)
        else:
            block.hash = block.compute_hash()
        self.chain.append(block)
        return block

    def append_verified_block(self, block: Block) -> bool:
        """Accept a block mined by another node after verifying it."""
        if block.previous_hash != self.last_block.hash:
            return False
        if block.hash != block.compute_hash():
            return False
        prefix = "0" * self.difficulty
        if not block.hash.startswith(prefix):
            return False
        self.chain.append(block)
        return True

    def is_valid(self) -> bool:
        for i in range(1, len(self.chain)):
            cur  = self.chain[i]
            prev = self.chain[i - 1]
            if cur.hash != cur.compute_hash():
                return False
            if cur.previous_hash != prev.hash:
                return False
        return True

    def to_list(self) -> list:
        return [b.to_dict() for b in self.chain]


# ─── Multi-node network ───────────────────────────────────────────────────────

class BlockchainNetwork:
    """
    Simulates a 3-node permissioned blockchain network.
    Node-A is the primary detection node that mines blocks.
    Node-B and Node-C are peer nodes that verify and replicate.
    """

    def __init__(self):
        self.nodes = {
            nid: NodeChain(nid, difficulty=config.MINING_DIFFICULTY)
            for nid in config.BLOCKCHAIN_NODES
        }
        self.primary_node = config.BLOCKCHAIN_NODES[0]   # "node-A"
        self._attack_counter = 0

    def add_attack(self, attack_record: dict) -> dict:
        """
        Primary node mines a block, then broadcasts to peers.
        Returns block info dict.
        """
        self._attack_counter += 1
        attack_record["attack_id"] = attack_record.get(
            "attack_id", f"DDOS-{self._attack_counter:05d}"
        )

        # Mine on primary node
        primary = self.nodes[self.primary_node]
        block = primary.add_block(attack_record, mine=True)

        # Broadcast to peers
        accepted_by = [self.primary_node]
        for node_id, node_chain in self.nodes.items():
            if node_id == self.primary_node:
                continue
            # Sync chain length first if behind
            if len(node_chain.chain) < len(primary.chain) - 1:
                node_chain.chain = list(primary.chain[:-1])
            ok = node_chain.append_verified_block(block)
            if ok:
                accepted_by.append(node_id)

        return {
            "index":       block.index,
            "hash":        block.hash,
            "timestamp":   block.timestamp,
            "attack_id":   attack_record["attack_id"],
            "node":        self.primary_node,
            "accepted_by": accepted_by,
            "nonce":       block.nonce,
        }

    def get_chain(self) -> list:
        return self.nodes[self.primary_node].to_list()

    def verify(self) -> dict:
        results = {}
        for nid, node in self.nodes.items():
            results[nid] = node.is_valid()
        all_valid = all(results.values())
        return {"valid": all_valid, "nodes": results, "block_count": len(self.nodes[self.primary_node].chain)}

    def get_block_count(self) -> int:
        return len(self.nodes[self.primary_node].chain) - 1  # exclude genesis

    def get_node_status(self) -> dict:
        return {
            nid: {
                "chain_length": len(node.chain),
                "is_valid": node.is_valid(),
                "last_block_hash": node.last_block.hash[:16] + "...",
            }
            for nid, node in self.nodes.items()
        }


# Singleton
blockchain = BlockchainNetwork()

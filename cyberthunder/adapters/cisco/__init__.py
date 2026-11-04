"""Cisco IOS / IOS-XE network device adapter (switches and routers).

Works from running-config text: NDM, L2S and RTR STIG checks, a configuration intrusion hunt, and
config-snippet fixes applied to a saved config, the simulated demo switch, or a live device over SSH
(only when the target allows push). Importing this package registers the adapter.
"""
from .adapter import CiscoIOSAdapter, runbook_steps, validate_payload
from .hunt import HuntHit, hunt_config
from .parser import ConfigModel, parse_config, render, tokenize
from .rules import Rule, applicable_rules, evaluate, load_rules, resolve_options, rules_by_id
from .snippet import apply_snippet, inverse_snippet, unified_diff
from .transports import ConfigFileTransport, IOSCli, SimulatedTransport

__all__ = ["CiscoIOSAdapter", "ConfigFileTransport", "SimulatedTransport", "IOSCli", "ConfigModel", "Rule",
           "HuntHit", "parse_config", "tokenize", "render", "apply_snippet", "inverse_snippet", "unified_diff",
           "load_rules", "rules_by_id", "applicable_rules", "evaluate", "resolve_options", "hunt_config",
           "runbook_steps", "validate_payload"]

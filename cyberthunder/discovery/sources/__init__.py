"""Discovery sources. Each module turns one tool's output into DiscoveredAsset stubs.

Parsers are pure functions of text so they are tested from fixtures. Command builders use fixed option
tables and validated addresses only; nothing from free text or a model is ever placed on a command line.
"""

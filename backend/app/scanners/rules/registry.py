"""
PatchForge AI - Vulnerability Rule Registry
===========================================
Centralized registry indexing all active AST vulnerability detection rules.
"""

from typing import Dict, List, Optional
from app.scanners.rules.base_rule import BaseRule
from app.scanners.rules.python.sqli import PythonSQLInjectionRule
from app.scanners.rules.python.cmd_injection import PythonCommandInjectionRule
from app.scanners.rules.python.path_traversal import PythonPathTraversalRule
from app.scanners.rules.python.unsafe_deserialization import PythonUnsafeDeserializationRule
from app.scanners.rules.python.hardcoded_secrets import PythonHardcodedSecretRule
from app.scanners.rules.python.insecure_tls import PythonInsecureTLSRule
from app.scanners.rules.python.eval_injection import PythonEvalCodeInjectionRule
from app.scanners.rules.python.weak_hash import PythonWeakCryptoHashRule
from app.scanners.rules.python.unsafe_yaml import PythonUnsafeYAMLRule
from app.scanners.rules.javascript.sqli import JavaScriptSQLInjectionRule
from app.scanners.rules.javascript.cmd_injection import JavaScriptCommandInjectionRule
from app.scanners.rules.javascript.path_traversal import JavaScriptPathTraversalRule


class RuleRegistry:
    """Manages discovery and language dispatching of AST security rules."""

    def __init__(self):
        self._rules: Dict[str, BaseRule] = {}
        self._register_default_rules()

    def _register_default_rules(self):
        default_rules = [
            # Python Rules
            PythonSQLInjectionRule(),
            PythonCommandInjectionRule(),
            PythonPathTraversalRule(),
            PythonUnsafeDeserializationRule(),
            PythonHardcodedSecretRule(),
            PythonInsecureTLSRule(),
            PythonEvalCodeInjectionRule(),
            PythonWeakCryptoHashRule(),
            PythonUnsafeYAMLRule(),
            # JavaScript Rules
            JavaScriptSQLInjectionRule(),
            JavaScriptCommandInjectionRule(),
            JavaScriptPathTraversalRule(),
        ]
        for rule in default_rules:
            self.register_rule(rule)

    def register_rule(self, rule: BaseRule):
        """Registers a new or custom vulnerability rule."""
        self._rules[rule.rule_id] = rule

    def get_rule_by_id(self, rule_id: str) -> Optional[BaseRule]:
        """Retrieves rule by its unique identifier (e.g. PY-SQLI-001)."""
        return self._rules.get(rule_id)

    def get_rules_for_language(self, language: str) -> List[BaseRule]:
        """Returns all registered rules applicable to a specific language."""
        lang_lower = language.lower()
        return [rule for rule in self._rules.values() if rule.language.lower() == lang_lower]

    def get_all_rules(self) -> List[BaseRule]:
        """Returns all active rules in the platform."""
        return list(self._rules.values())


# Global singleton instance
rule_registry = RuleRegistry()

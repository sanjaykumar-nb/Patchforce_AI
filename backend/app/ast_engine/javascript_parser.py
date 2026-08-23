"""
PatchForge AI - Tree-sitter JavaScript AST Parser
=================================================
Implements fast, memory-safe AST analysis using TreeCursor traversal:
function declarations, arrow functions, calls, require/import statements,
and scope extraction.
"""

from typing import Any, List, Optional
import tree_sitter_javascript as tsjavascript
from tree_sitter import Language, Parser, Node
from app.ast_engine.base import BaseASTParser, ASTNodeData


class JavaScriptASTParser(BaseASTParser):
    """Production Tree-sitter AST parser for JavaScript / TypeScript with TreeCursor traversal."""

    def __init__(self):
        super().__init__(language_name="javascript")
        self.language = Language(tsjavascript.language())
        self.parser = Parser(self.language)

    def parse(self, source_code: str) -> Any:
        """Parses JavaScript source code string into a Tree-sitter tree."""
        source_bytes = source_code.encode("utf-8")
        return self.parser.parse(source_bytes)

    def _node_to_data(self, node: Node, source_bytes: bytes, parent_scope: Optional[str] = None) -> ASTNodeData:
        """Converts a Tree-sitter Node into normalized ASTNodeData."""
        text = source_bytes[node.start_byte:node.end_byte].decode("utf-8", errors="replace")
        return ASTNodeData(
            node_type=node.type,
            start_line=node.start_point.row + 1,
            start_column=node.start_point.column,
            end_line=node.end_point.row + 1,
            end_column=node.end_point.column,
            text=text,
            parent_scope=parent_scope,
        )

    def _walk_tree(self, tree):
        """Yields every node in the tree using safe iterative stack traversal with cycle protection."""
        if not tree or not tree.root_node:
            return
        try:
            stack = [tree.root_node]
            seen = set()
            while stack:
                node = stack.pop()
                node_id = (node.start_byte, node.end_byte, node.type)
                if node_id in seen:
                    continue
                seen.add(node_id)
                yield node
                for child in reversed(node.children):
                    if (child.start_byte, child.end_byte, child.type) not in seen:
                        stack.append(child)
        except Exception:
            return

    def get_functions(self, source_code: str) -> List[ASTNodeData]:
        """Extracts function declarations, arrow functions, and class methods."""
        tree = self.parse(source_code)
        source_bytes = source_code.encode("utf-8")
        functions = []

        for node in self._walk_tree(tree):
            if node.type in ("function_declaration", "generator_function_declaration", "method_definition"):
                func_name = None
                for child in node.children:
                    if child.type in ("identifier", "property_identifier"):
                        func_name = source_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                        break
                node_data = self._node_to_data(node, source_bytes)
                node_data.identifier = func_name
                functions.append(node_data)

            elif node.type == "variable_declarator":
                var_name = None
                has_func = False
                for child in node.children:
                    if child.type == "identifier":
                        var_name = source_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                    elif child.type in ("arrow_function", "function_expression"):
                        has_func = True

                if has_func:
                    node_data = self._node_to_data(node, source_bytes)
                    node_data.identifier = var_name
                    functions.append(node_data)

        return functions

    def get_classes(self, source_code: str) -> List[ASTNodeData]:
        """Extracts all class declarations."""
        tree = self.parse(source_code)
        source_bytes = source_code.encode("utf-8")
        classes = []

        for node in self._walk_tree(tree):
            if node.type == "class_declaration":
                class_name = None
                for child in node.children:
                    if child.type == "identifier":
                        class_name = source_bytes[child.start_byte:child.end_byte].decode("utf-8", errors="replace")
                        break
                node_data = self._node_to_data(node, source_bytes)
                node_data.identifier = class_name
                classes.append(node_data)

        return classes

    def get_imports(self, source_code: str) -> List[ASTNodeData]:
        """Extracts ES6 import statements and CommonJS require() calls."""
        tree = self.parse(source_code)
        source_bytes = source_code.encode("utf-8")
        imports = []

        for node in self._walk_tree(tree):
            if node.type == "import_statement":
                imports.append(self._node_to_data(node, source_bytes))
            elif node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                if func_node:
                    func_name = source_bytes[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")
                    if func_name == "require":
                        imports.append(self._node_to_data(node, source_bytes))

        return imports

    def get_calls(self, source_code: str, target_name: Optional[str] = None) -> List[ASTNodeData]:
        """Extracts all function and method call sites."""
        tree = self.parse(source_code)
        source_bytes = source_code.encode("utf-8")
        calls = []

        for node in self._walk_tree(tree):
            if node.type == "call_expression":
                func_node = node.child_by_field_name("function")
                call_name = None
                if func_node:
                    call_name = source_bytes[func_node.start_byte:func_node.end_byte].decode("utf-8", errors="replace")

                if target_name is None or (call_name and target_name in call_name):
                    node_data = self._node_to_data(node, source_bytes)
                    node_data.identifier = call_name
                    calls.append(node_data)

        return calls

    def get_assignments(self, source_code: str) -> List[ASTNodeData]:
        """Extracts assignment expressions and variable declarators."""
        tree = self.parse(source_code)
        source_bytes = source_code.encode("utf-8")
        assignments = []

        for node in self._walk_tree(tree):
            if node.type in ("assignment_expression", "augmented_assignment_expression", "variable_declarator"):
                assignments.append(self._node_to_data(node, source_bytes))

        return assignments

    def find_enclosing_function(
        self,
        source_code: str,
        line_number: int,
        line_end: Optional[int] = None,
    ) -> Optional[ASTNodeData]:
        """Locates the tightest function node enclosing or overlapping the given line range."""
        functions = self.get_functions(source_code)
        candidate = None
        end_num = line_end or line_number

        for func in functions:
            if not (end_num < func.start_line or line_number > func.end_line):
                if candidate is None:
                    candidate = func
                else:
                    if (func.end_line - func.start_line) < (candidate.end_line - candidate.start_line):
                        candidate = func

        return candidate

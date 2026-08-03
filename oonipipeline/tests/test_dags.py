"""
Static checks on the Airflow DAG definitions.

These are deliberately AST-based rather than importing the DAG module: importing
it requires an Airflow runtime with a metadata DB for ``Variable.get``, which
isn't available in unit tests. Parsing gets us the one check that actually
matters here — that every ``op_kwargs`` key is a parameter the ``python_callable``
will accept. Airflow passes ``op_kwargs`` straight through as keyword arguments,
so a stale key is a ``TypeError`` at task runtime rather than at parse time, and
therefore isn't caught by anything else.
"""

import ast
from pathlib import Path
from typing import Dict, List, Set, Tuple

import pytest

DAGS_DIR = Path(__file__).parent.parent.parent / "dags"
DAG_FILES = sorted(DAGS_DIR.glob("*.py"))


def _function_params(tree: ast.Module) -> Dict[str, Set[str]]:
    """Map every top-level function name to the set of keyword names it accepts."""
    params = {}
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        args = node.args
        if args.kwarg is not None:
            # accepts **kwargs, so any key is valid
            params[node.name] = None
            continue
        names = {a.arg for a in args.args} | {a.arg for a in args.kwonlyargs}
        params[node.name] = names
    return params


def _operator_calls(tree: ast.Module) -> List[Tuple[str, Set[str], int]]:
    """Find (callable_name, op_kwargs_keys, lineno) for every operator call."""
    calls = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call):
            continue
        callable_name = None
        op_kwargs = None
        for kw in node.keywords:
            if kw.arg == "python_callable" and isinstance(kw.value, ast.Name):
                callable_name = kw.value.id
            elif kw.arg == "op_kwargs" and isinstance(kw.value, ast.Dict):
                op_kwargs = {
                    k.value
                    for k in kw.value.keys
                    if isinstance(k, ast.Constant) and isinstance(k.value, str)
                }
        if callable_name is not None and op_kwargs is not None:
            calls.append((callable_name, op_kwargs, node.lineno))
    return calls


@pytest.mark.parametrize("dag_file", DAG_FILES, ids=lambda p: p.name)
def test_op_kwargs_match_callable_signature(dag_file: Path):
    tree = ast.parse(dag_file.read_text())
    params = _function_params(tree)

    calls = _operator_calls(tree)
    assert calls, f"no operator calls found in {dag_file.name} — parser out of date?"

    for callable_name, op_kwargs, lineno in calls:
        assert (
            callable_name in params
        ), f"{dag_file.name}:{lineno} references undefined callable {callable_name}"
        accepted = params[callable_name]
        if accepted is None:
            continue
        unexpected = op_kwargs - accepted
        assert not unexpected, (
            f"{dag_file.name}:{lineno} passes op_kwargs {sorted(unexpected)} "
            f"which {callable_name}() does not accept "
            f"(accepts: {sorted(accepted)}). Airflow forwards op_kwargs as "
            f"keyword arguments, so this raises TypeError at task runtime."
        )

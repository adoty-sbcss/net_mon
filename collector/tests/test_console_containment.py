"""Remote console: the fixed-argv containment property (CON-5 security review).

The restricted console's ONE security control is that nothing an operator supplies
reaches execution. The threat modelled is not a rogue admin — it is a compromise of
the dashboard -> broker -> sensor chain being used to pivot into a district's
internal network. So the property that has to hold is: given full control of the
operator browser AND the broker, an attacker can still only cause the sensor to run
a bounded set of commands, with arguments the SENSOR chose.

`_DIAG_COMMANDS` / `_CONTROL_COMMANDS` hold that structurally — the argv is a
literal list, so there is nowhere to inject. `_LIVE_OPS` does not: it re-enters
`_run_command`, and is contained only because that function takes the command id
and nothing else. These tests pin the parts that a future edit could break
silently, since none of them would raise a type error or fail an existing test:

  1. `_run_command` keeps its single-parameter signature (no channel for operator
     data to arrive on).
  2. `remote_console` only ever calls it as `_run_command(<one name>)` — checked
     on the AST, so a `_run_command(cmd_id, frame["target"])` cannot slip in.
  3. The fixed-argv registries stay literal — no format placeholders that a later
     `.format()` / `%` could fill from a frame.
  4. The console dispatch reads exactly one field off the frame: `id`.

These are structural assertions on purpose. They are cheap, they never touch the
box, and they fail loudly at the moment the containment property is weakened
rather than at the moment it is exploited.
"""
from __future__ import annotations

import ast
import inspect
import json
from pathlib import Path

from collector import remote_console as rc
from collector.checkin import (
    _CONTROL_COMMANDS,
    _DIAG_COMMANDS,
    _LIVE_OPS,
    _QUEUED_ONLY_COMMANDS,
    _run_command,
)

# Anything that could be filled in later from operator-supplied data. `%` is
# deliberately absent: `ip -s neigh flush all` and friends carry no percent signs
# today, but a legitimate future argv might, and the f-string/format/%-format
# vectors below are the ones that actually take a value.
_PLACEHOLDERS = ("{}", "{0", "%s", "%d", "$1", "$@", "$*")


def test_run_command_takes_only_the_command_id():
    """The single channel into the rich handlers stays one string wide.

    If this grows a second parameter, `_LIVE_OPS` handlers can start receiving
    operator-supplied data and the allow-list stops being containment.
    """
    sig = inspect.signature(_run_command)
    params = list(sig.parameters.values())
    assert len(params) == 1, (
        f"_run_command must take exactly the command id, got {sig}. "
        "A second parameter is a channel for operator-supplied data — see the "
        "containment invariant on _LIVE_OPS in checkin.py."
    )
    (only,) = params
    # checkin.py uses `from __future__ import annotations`, so the annotation
    # arrives as the string "str" rather than the type itself.
    assert only.annotation in (str, "str"), (
        f"the command id must stay a plain str, got {only.annotation!r}"
    )
    assert only.kind is inspect.Parameter.POSITIONAL_OR_KEYWORD


def test_remote_console_calls_run_command_with_exactly_one_plain_name():
    """AST check: no call site may pass anything but a bare local name.

    Catches the specific regression the invariant guards against — someone
    threading a frame field through, e.g. `_run_command(cmd_id, frame["target"])`
    or `_run_command(cmd_id, target=frame.get("ip"))`.
    """
    src = Path(inspect.getfile(rc)).read_text(encoding="utf-8")
    tree = ast.parse(src)
    calls = [
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.Call)
        and isinstance(node.func, ast.Name)
        and node.func.id == "_run_command"
    ]
    assert calls, "expected remote_console to call _run_command (did it get renamed?)"
    for call in calls:
        assert len(call.args) == 1 and not call.keywords, (
            "remote_console must call _run_command(<command id>) and nothing more; "
            f"found a call with {len(call.args)} positional / "
            f"{len(call.keywords)} keyword args on line {call.lineno}"
        )
        assert isinstance(call.args[0], ast.Name), (
            "the command id must be a plain local name (the re-validated frame id), "
            f"not a computed expression, on line {call.lineno}"
        )


def test_fixed_argv_registries_contain_no_placeholders():
    """`_DIAG_COMMANDS` / `_CONTROL_COMMANDS` argv must be fully literal.

    A placeholder is how a fixed-argv list quietly stops being fixed: the argv
    looks like a constant, but a later `.format(**frame)` turns it into a
    template. Nothing operator-supplied should have anywhere to land.
    """
    for registry_name, registry in (
        ("_DIAG_COMMANDS", _DIAG_COMMANDS),
        ("_CONTROL_COMMANDS", _CONTROL_COMMANDS),
    ):
        for cmd_id, argv in registry.items():
            assert isinstance(argv, list) and argv, f"{registry_name}[{cmd_id}] must be a non-empty argv list"
            for token in argv:
                assert isinstance(token, str), (
                    f"{registry_name}[{cmd_id}] argv must be all strings, got {type(token)}"
                )
                for ph in _PLACEHOLDERS:
                    assert ph not in token, (
                        f"{registry_name}[{cmd_id}] contains the placeholder {ph!r}. "
                        "Fixed-argv means literal — a template is an injection point."
                    )


def test_live_ops_and_fixed_argv_registries_do_not_overlap():
    """An id in both would dispatch by whichever branch runs first, so the
    reviewed safety model for it would depend on dispatch order rather than on
    the registry it was added to."""
    assert not (_LIVE_OPS & set(_DIAG_COMMANDS)), "id is in both _LIVE_OPS and _DIAG_COMMANDS"
    assert not (_LIVE_OPS & set(_CONTROL_COMMANDS)), "id is in both _LIVE_OPS and _CONTROL_COMMANDS"
    assert not (set(_DIAG_COMMANDS) & set(_CONTROL_COMMANDS)), (
        "id is in both _DIAG_COMMANDS and _CONTROL_COMMANDS"
    )


def test_queued_only_commands_are_refused_on_a_live_session():
    """The SENSOR must refuse queued-only ids, not just the broker.

    The broker omits these from its relay allow-list, but the broker is inside
    the threat model — an invariant only it enforces is enforced only by a
    component an attacker may own. The sensor has to be at least as strict.
    """
    assert _QUEUED_ONLY_COMMANDS, "expected at least one queued-only id"

    class _WS:
        """Collects frames; takes its sink explicitly so it binds no loop var."""

        def __init__(self, sink: list[dict]) -> None:
            self._sink = sink

        def send(self, raw: str) -> None:
            self._sink.append(json.loads(raw))

    for cmd_id in _QUEUED_ONLY_COMMANDS:
        sent: list[dict] = []
        # If this ever actually executed, it would shell out; the refusal has to
        # happen before the registry lookup, so nothing runs.
        rc._run_diag_stream(_WS(sent), cmd_id)

        assert len(sent) == 1, f"{cmd_id}: expected exactly one refusal frame, got {sent}"
        assert sent[0]["type"] == "err"
        assert sent[0]["id"] == cmd_id
        assert "live session" in sent[0]["message"]
        # Crucially: it must NOT have started running.
        assert not [f for f in sent if f.get("type") in ("begin", "out", "exit")]


def test_queued_only_ids_are_real_registry_ids():
    """A stale entry would silently shrink the live allow-list without anyone
    noticing — the id would look 'blocked' while simply not existing."""
    union = set(_DIAG_COMMANDS) | set(_CONTROL_COMMANDS) | set(_LIVE_OPS)
    unknown = _QUEUED_ONLY_COMMANDS - union
    assert not unknown, f"_QUEUED_ONLY_COMMANDS has ids in no registry: {sorted(unknown)}"


def test_console_dispatch_reads_only_the_id_off_a_cmd_frame():
    """The restricted session loop must take nothing but `id` from a `cmd` frame.

    Read off the AST of run_console_session: collect every `frame.get("…")` key
    it reads, and pin the set. `mode`/`data`/`cols`/`rows` belong to the
    full-shell (CON-7) bridge, which is a different, step-up-gated posture; the
    restricted path's command handling gets `id` only.
    """
    src = Path(inspect.getfile(rc)).read_text(encoding="utf-8")
    tree = ast.parse(src)
    fn = next(
        node
        for node in ast.walk(tree)
        if isinstance(node, ast.FunctionDef) and node.name == "run_console_session"
    )
    keys: set[str] = set()
    for node in ast.walk(fn):
        if (
            isinstance(node, ast.Call)
            and isinstance(node.func, ast.Attribute)
            and node.func.attr == "get"
            and isinstance(node.func.value, ast.Name)
            and node.func.value.id == "frame"
            and node.args
            and isinstance(node.args[0], ast.Constant)
        ):
            keys.add(str(node.args[0].value))
    # `type` is read via frame.get("type") for dispatch; the rest are the
    # full-shell PTY relay fields. `id` is the ONLY one the allow-listed path uses.
    assert keys <= {"type", "id", "data", "cols", "rows"}, (
        f"run_console_session reads unexpected frame fields: {sorted(keys)}. "
        "Every new field read from an operator frame is operator-controlled input "
        "— see the containment invariant on _LIVE_OPS in checkin.py."
    )
    assert "id" in keys, "expected the command id to still be read off the frame"

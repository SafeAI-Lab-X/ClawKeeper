"""Bounded, non-executing command views for the execution gate.

Parse Bash syntax rather than searching documentation, comments and inline
Python as if they were shell commands. These views identify visible calls;
they are not a proof of arbitrary program safety. Unsupported executable text
and incomplete parsing raise AnalysisIncomplete, never a clean result.

Implemented independently using upstream tree-sitter and Python's ast module.
"""

from __future__ import annotations

import ast
import io
import re
import shlex
import tokenize
from contextlib import contextmanager
from dataclasses import dataclass, field

import tree_sitter_bash
from tree_sitter import Language, Node, Parser

from clawkeeper_core.command_facts import (
    Analysis,
    DataSpan,
    Diagnostic,
    Invocation,
    Origin,
    Pipeline,
    Redirection,
    Source,
    Word,
)

MAX_SOURCE_BYTES = 100_000
MAX_DEPTH = 12
MAX_NODES = 20_000
_LANGUAGE = Language(tree_sitter_bash.language())
_SHELLS = {"bash", "sh", "dash", "zsh", "ksh"}
_PYTHON = re.compile(r"python(?:\d+(?:\.\d+)*)?$")
_CODE_FLAGS = {"node": "-e", "nodejs": "-e", "ruby": "-e", "perl": "-e", "php": "-r"}
_POPEN_EXECUTABLE_INDEX = 2


class AnalysisIncomplete(ValueError):
    """The gate cannot finish analysis of a visible execution entry point."""


def executable_name(value: str) -> str:
    """Lexical identity only: do not resolve PATH or read executable files."""
    name = value.replace("\\", "/").rsplit("/", 1)[-1].lower()
    for suffix in (".exe", ".cmd", ".bat", ".com"):
        if name.endswith(suffix):
            return name[: -len(suffix)]
    return name


@dataclass
class CommandAnalysis:
    sources: list[Source] = field(default_factory=list)
    invocations: list[Invocation] = field(default_factory=list)
    pipelines: list[Pipeline] = field(default_factory=list)
    diagnostics: list[Diagnostic] = field(default_factory=list)
    data: list[DataSpan] = field(default_factory=list)
    node_calls: dict[Origin, Invocation] = field(default_factory=dict)
    origin: Origin | None = None
    field: tuple[str, ...] = ()
    _remaining: int = MAX_NODES
    _bytes: int = MAX_SOURCE_BYTES

    def consume(self, size: int = 1) -> None:
        self._remaining -= size
        if self._remaining < 0:
            raise AnalysisIncomplete("command analysis node budget exhausted")

    def fail(self, reason: str) -> None:
        self.diagnostics.append(Diagnostic(reason, self.origin))

    def location(self, node: Node) -> Origin:
        return Origin(self.origin.source, node.start_byte, node.end_byte)

    @contextmanager
    def document(self, source: str, language: str, kind: str):
        previous = self.origin
        self.origin = Origin(len(self.sources), 0, len(source.encode()))
        self.sources.append(Source(language, source, kind, previous, self.field if previous is None else ()))
        try:
            yield
        except (AnalysisIncomplete, RecursionError, ValueError) as exc:
            self.fail(str(exc) or type(exc).__name__)
        finally:
            self.origin = previous

    def freeze(self) -> Analysis:
        return Analysis(tuple(self.sources), tuple(self.invocations), tuple(self.pipelines), tuple(self.diagnostics), tuple(self.data))

    def add(self, argv, literals, words=None, redirects=(), *, kind="process") -> Invocation:
        origin = self.origin
        words = words or [Word(a, a if i == 0 else literals[i - 1], origin=origin) for i, a in enumerate(argv)]
        name = executable_name(argv[0]) if kind == "process" else argv[0]
        arguments = _argument_roles(name, words[1:]) if kind == "process" else words[1:]
        call = Invocation(Word(words[0].raw, name, "operation" if kind == "python.operation" else "program", words[0].origin), tuple(arguments),
                          origin, self.sources[origin.source].language, tuple(redirects), _effective_stdin(redirects), kind)
        self.invocations.append(call)
        return call


def _argument_roles(name: str, words: list[Word]) -> list[Word]:
    from dataclasses import replace  # noqa: PLC0415

    arguments = [w.display for w in words]
    roles = ["option" if a.startswith("-") else "argument" for a in arguments]
    wrappers = {"sudo", "env", "command", "builtin", "exec", "nohup", "nice", "timeout", "time"}
    if name in _SHELLS | set(_CODE_FLAGS) or _PYTHON.fullmatch(name):
        mode, index, prefix = _interpreter_source(name, arguments, words)
        if mode == "inline":
            if index < len(words):
                roles[index:] = ["code", *(["data"] * (len(words) - index - 1))]
                if prefix:
                    word = words[index]
                    return [*words[:index], Word(prefix, prefix, "option", word.origin),
                            Word(word.raw, None if word.value is None else word.value[len(prefix):], "code", word.origin),
                            *(replace(w, role="data") for w in words[index + 1:])]
        elif mode == "module":
            operand = index + 1 if arguments[index] == "-m" else index
            if operand < len(words):
                roles[operand] = "module"
        elif mode == "file":
            roles[index] = "script"
    elif name in wrappers | {"cmd", "powershell", "pwsh", "eval", "source", ".", "echo", "printf"}:
        roles = ["data"] * len(words)
    else:
        flags = _data_flags(name)
        for i, arg in enumerate(arguments):
            if i and arguments[i - 1] in flags:
                roles[i] = "data"
            elif any(arg.startswith(flag + "=") for flag in flags):
                # Keep the option spelling; its complete value remains data.
                roles[i] = "metadata"
    return [replace(word, role=role) for word, role in zip(words, roles, strict=True)]


def _interpreter_source(name: str, args: list[str], words: list[Word] | None = None) -> tuple[str, int, str]:
    """Locate the source operand before interpreting script/module arguments.

    The index addresses argv without the program name. A nonempty prefix
    denotes an attached code flag such as Python's `-ccode`.
    """
    flag = "-c" if name in _SHELLS or _PYTHON.fullmatch(name) else _CODE_FLAGS[name]
    value_options = ({"--rcfile", "--init-file", "-o", "+o", "-O", "+O"}
                     if name in _SHELLS else {"-W", "-X", "-r", "--require", "--loader", "--import"})
    i = 0
    stdin = False
    while i < len(args):
        arg = args[i]
        if words is not None and not words[i].literal:
            raise AnalysisIncomplete("dynamic interpreter option or source operand")
        if arg == "--":
            i += 1
            break
        if _PYTHON.fullmatch(name) and (arg == "-m" or arg.startswith("-m")):
            operand = i + 1 if arg == "-m" else i
            if operand >= len(args) or (words is not None and not words[operand].literal):
                raise AnalysisIncomplete("dynamic or missing Python module")
            return "module", i, ""
        if arg == flag or (name in _SHELLS and arg.startswith("-") and not arg.startswith("--") and "c" in arg):
            return "inline", i + 1, ""
        if name not in _SHELLS and arg.startswith(flag):
            return "inline", i, flag
        if name in _SHELLS and arg.startswith("-") and not arg.startswith("--") and "s" in arg:
            stdin = True
        if arg in value_options:
            i += 2
        elif arg == "-" or not arg.startswith(("-", "+")):
            break
        else:
            i += 1
    return ("stdin" if stdin or i >= len(args) or args[i] == "-" else "file"), i, ""


def _data_flags(name: str) -> set[str]:
    """Common metadata slots only; code-bearing flags are never data slots."""
    return {
        "git": {"-m", "--message", "--grep"},
        "gh": {"-t", "--title", "-b", "--body", "--body-file"},
        "grep": {"-e", "--regexp"},
        "rg": {"-e", "--regexp"},
    }.get(name, set())


def _text(node: Node) -> str:
    return node.text.decode("utf-8")


def _literal(node: Node) -> str | None:  # noqa: PLR0911 -- token-kind decoding
    """Decode quoting only; expansions are intentionally never evaluated."""
    if node.type == "command_name":
        return _literal(node.named_children[0]) if node.named_children else None
    if node.type == "string_content":
        return _text(node)
    if node.type not in {
        "word",
        "number",
        "string",
        "raw_string",
        "concatenation",
        "string_content",
    }:
        return None
    if any(_literal(c) is None for c in node.named_children):
        return None
    value = _text(node)
    if node.type == "word" and re.match(r"(?:[A-Za-z]:|\.{1,2})\\", value):
        return value  # literal Windows executable/path, not POSIX backslash removal
    try:
        words = shlex.split(value)
    except ValueError:
        return None
    return words[0] if len(words) == 1 else ("" if value in {"''", '""'} else None)


def _argv(node: Node) -> tuple[list[str], list[str | None]]:
    name = node.child_by_field_name("name")
    if name is None or (program := _literal(name)) is None:
        raise AnalysisIncomplete("dynamic or missing command name")
    args = [_literal(arg) for arg in node.children_by_field_name("argument")]
    return [
        program,
        *(
            a if a is not None else _text(n)
            for a, n in zip(args, node.children_by_field_name("argument"), strict=True)
        ),
    ], args


def _unwrap(argv: list[str]) -> list[str] | None:
    """Known launcher option shapes only. Ambiguous options require review."""
    name = executable_name(argv[0])
    i = 1
    value_options = {
        "sudo": {"-u", "-g", "-h", "-p", "-C", "-T", "-R", "-D", "--user", "--group"},
        "env": {"-u", "--unset", "-C", "--chdir"},
        "nice": {"-n", "--adjustment"},
        "timeout": {"-s", "--signal", "-k", "--kill-after"},
    }
    flag_options = {
        "sudo": {"-n", "-E", "-H", "-S", "--non-interactive"},
        "env": {"-i", "--ignore-environment"},
        "command": {"-p"},
        "builtin": set(),
        "time": {"-p"},
        "exec": {"-c", "-l"},
        "nohup": set(),
        "nice": set(),
        "timeout": {"--foreground", "--preserve-status", "-v"},
    }
    if name not in flag_options:
        return None
    if name == "command" and argv[1:2] in (["-v"], ["-V"]):
        return []  # query, not execution
    while i < len(argv):
        arg = argv[i]
        if arg == "--":
            i += 1
            break
        if name == "env" and re.fullmatch(r"[A-Za-z_][A-Za-z_0-9]*=.*", arg, re.DOTALL):
            i += 1
        elif arg in value_options.get(name, set()):
            i += 2
        elif arg in flag_options[name] or (
            "=" in arg and arg.split("=", 1)[0] in value_options.get(name, set())
        ):
            i += 1
        elif arg.startswith("-"):
            raise AnalysisIncomplete(f"unsupported {name} launcher option")
        else:
            break
    if name == "timeout":
        i += 1  # duration
    return argv[i:]


def _inspect_argv(  # noqa: PLR0912, PLR0917 -- dispatch and shared parser state
    argv: list[str],
    literals: list[str | None],
    result: CommandAnalysis,
    depth: int,
    redirects: tuple[Redirection, ...] = (),
    words: list[Word] | None = None,
) -> None:
    if depth > MAX_DEPTH:
        raise AnalysisIncomplete("nested execution depth exceeded")
    result.consume()
    result.add(argv, literals, words, redirects)
    inner = _unwrap(argv)
    if inner is not None:
        if inner:
            start = len(argv) - len(inner)
            # Only the launcher's prefix and program identity must be literal.
            # Preserve dynamic argument markers through every wrapper layer.
            if any(x is None for x in literals[:start]):
                raise AnalysisIncomplete("dynamic launcher arguments")
            _inspect_argv(inner, literals[start:], result, depth + 1, redirects,
                          words[start:] if words else None)
        return
    name = executable_name(argv[0])
    args = argv[1:]
    if name in _SHELLS or _PYTHON.fullmatch(name) or name in _CODE_FLAGS:
        argument_words = words[1:] if words else [Word(a, v, origin=result.origin) for a, v in zip(args, literals, strict=True)]
        mode, code_index, prefix = _interpreter_source(name, args, argument_words)
        if mode == "file" and literals[code_index] is None and args[code_index].startswith(("<(", ">(")):
            raise AnalysisIncomplete("process substitution supplies executable text")
        if mode == "inline":
            if code_index >= len(args) or literals[code_index] is None:
                raise AnalysisIncomplete("dynamic or missing inline code")
            code = args[code_index][len(prefix):]
            parent_origin = result.origin
            result.origin = argument_words[code_index].origin or parent_origin
            if name in _SHELLS:
                _shell(code, result, depth + 1)
            elif _PYTHON.fullmatch(name):
                _python(code, result, depth + 1)
            else:
                raise AnalysisIncomplete(f"inline {name} analysis is not supported")
            result.origin = parent_origin
    elif name in {"eval", "source", "."}:
        if any(a is None for a in literals) or name != "eval":
            raise AnalysisIncomplete("dynamic or external executable text")
        _shell(" ".join(args[1:] if args[:1] == ["--"] else args), result, depth + 1)
    elif name == "cmd":
        if args and args[0].lower() in {"/c", "/k"}:
            if any(a is None for a in literals) or any("%" in a or "^" in a for a in args[1:]):
                raise AnalysisIncomplete("Cmd expansion or escaping requires review")
            _shell(" ".join(args[1:]), result, depth + 1)
    elif name in {"powershell", "pwsh"}:
        raise AnalysisIncomplete("PowerShell executable text requires review")
    elif name in {"xargs", "find"}:
        # find's read-only expressions are not launchers. Its exec actions and
        # xargs can hide a program behind options and runtime-generated argv.
        if name == "xargs" or any(a in {"-exec", "-execdir", "-ok", "-okdir"} for a in args):
            raise AnalysisIncomplete("indirect program launcher requires review")


def _python(code: str, result: CommandAnalysis, depth: int, *, kind: str | None = None) -> None:
    with result.document(code, "python", kind or ("tool" if result.origin is None else "inline")):
        _python_body(code, result, depth)


def _python_body(code: str, result: CommandAnalysis, depth: int) -> None:  # noqa: PLR0912, PLR0915 -- supported AST calls and process options
    if depth > MAX_DEPTH:
        raise AnalysisIncomplete("nested execution depth exceeded")
    result._bytes -= len(code.encode())
    if result._bytes < 0:
        raise AnalysisIncomplete("nested source budget exhausted")
    try:
        tree = ast.parse(code)
    except (SyntaxError, ValueError, RecursionError) as exc:
        raise AnalysisIncomplete("invalid inline Python") from exc
    aliases: dict[str, str] = {}
    offsets = [0]
    for line in code.encode().splitlines(keepends=True):
        offsets.append(offsets[-1] + len(line))
    nodes = list(ast.walk(tree))
    result.consume(len(nodes))
    for node in nodes:
        if isinstance(node, ast.Import):
            aliases.update((n.asname or n.name, n.name) for n in node.names)
        elif isinstance(node, ast.ImportFrom) and node.module:
            aliases.update((n.asname or n.name, f"{node.module}.{n.name}") for n in node.names)

    source_id = result.origin.source

    def location(node: ast.AST) -> Origin:
        return Origin(source_id, offsets[node.lineno - 1] + node.col_offset,
                      offsets[node.end_lineno - 1] + node.end_col_offset)

    shadowed = {n.id for n in nodes if isinstance(n, ast.Name) and isinstance(n.ctx, ast.Store)}
    shadowed.update(n.arg for n in nodes if isinstance(n, ast.arg))
    shadowed.update(aliases)
    for node in nodes:
        if isinstance(node, ast.Expr) and isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            result.data.append(DataSpan(location(node.value), "standalone literal"))
    lines = code.splitlines(keepends=True)
    for token in tokenize.generate_tokens(io.StringIO(code).readline):
        if token.type == tokenize.COMMENT:
            start = offsets[token.start[0] - 1] + len(lines[token.start[0] - 1][:token.start[1]].encode())
            end = offsets[token.end[0] - 1] + len(lines[token.end[0] - 1][:token.end[1]].encode())
            result.data.append(DataSpan(Origin(source_id, start, end), "comment"))

    def dotted(node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return aliases.get(node.id, node.id)
        if isinstance(node, ast.Attribute):
            return f"{dotted(node.value)}.{node.attr}"
        return ""

    for node in nodes:
        if not isinstance(node, ast.Call):
            continue
        # ast columns and tree-sitter offsets both count UTF-8 bytes.
        result.origin = location(node)
        fn = dotted(node.func)
        direct_file_write = (
            isinstance(node.func, ast.Attribute) and node.func.attr == "write"
            and isinstance(node.func.value, ast.Call)
            and (dotted(node.func.value.func) == "builtins.open"
                 or (dotted(node.func.value.func) == "open" and "open" not in shadowed))
        )
        if (fn == "print" and "print" not in shadowed) or fn == "builtins.print" or direct_file_write:
            for arg in node.args:
                if isinstance(arg, ast.Constant) and isinstance(arg.value, str):
                    result.data.append(DataSpan(location(arg), "literal output data"))
        if fn in {"eval", "exec", "builtins.eval", "builtins.exec"}:
            raise AnalysisIncomplete("dynamic Python execution requires review")
        shell_call = fn in {
            "os.system",
            "os.popen",
            "subprocess.getoutput",
            "subprocess.getstatusoutput",
        }
        process_call = fn in {
            "subprocess.run",
            "subprocess.call",
            "subprocess.check_call",
            "subprocess.check_output",
            "subprocess.Popen",
        }
        if not (shell_call or process_call):
            # A script-body learned rule can inspect actual non-process calls,
            # but assignments, docstrings and print arguments are not calls to
            # programs. Use one operation per view; never concatenate a body.
            if fn and not fn.startswith(".") and fn not in {"print", "builtins.print", "str", "repr", "json.loads"}:
                operation = "python:" + fn
                arguments = [] if fn.rsplit(".", 1)[-1] in {"write", "write_text", "write_bytes"} else node.args
                words = [Word(ast.unparse(node.func), operation, "operation", location(node.func))]
                for argument in arguments:
                    try:
                        literal = ast.literal_eval(argument)
                        literal = literal if isinstance(literal, str) else ast.unparse(argument)
                    except (ValueError, TypeError, RecursionError):
                        literal = None
                    words.append(Word(ast.unparse(argument), literal, origin=location(argument)))
                result.add([operation, *(w.raw for w in words[1:])], [], words, kind="python.operation")
            continue
        value = (
            node.args[0]
            if node.args
            else next((k.value for k in node.keywords if k.arg == "args"), None)
        )
        try:
            if any(k.arg is None for k in node.keywords):
                raise AnalysisIncomplete("dynamic Python process keyword arguments")
            command = ast.literal_eval(value) if value is not None else None
            shell = next(
                (ast.literal_eval(k.value) for k in node.keywords if k.arg == "shell"), False
            )
            executable = next(
                (ast.literal_eval(k.value) for k in node.keywords if k.arg == "executable"),
                ast.literal_eval(node.args[_POPEN_EXECUTABLE_INDEX])
                if process_call and len(node.args) > _POPEN_EXECUTABLE_INDEX else None,
            )
        except (ValueError, TypeError, RecursionError) as exc:
            raise AnalysisIncomplete("dynamic Python process arguments") from exc
        if executable is not None and (not isinstance(executable, str) or not executable):
            raise AnalysisIncomplete("unsupported Python process executable")
        if shell_call or shell:
            if not isinstance(command, str):
                raise AnalysisIncomplete("nonliteral Python shell command")
            if executable is None:
                _shell(command, result, depth + 1)
            else:
                _inspect_argv([executable, "-c", command], ["-c", command], result, depth + 1)
        elif (
            isinstance(command, (list, tuple))
            and command
            and all(isinstance(a, str) for a in command)
        ):
            _inspect_argv([executable or command[0], *command[1:]], list(command[1:]), result, depth + 1)
        elif isinstance(command, str):
            _inspect_argv([executable or command], [], result, depth + 1)
        else:
            raise AnalysisIncomplete("nonliteral Python process command")


def _stage_commands(node: Node) -> list[Node]:
    """Unwrap stage structure without descending into arguments or code data."""
    if node.type == "command":
        return [node]
    if node.type == "redirected_statement":
        body = node.child_by_field_name("body")
        if body is not None:
            return _stage_commands(body)
    if node.type in {"subshell", "compound_statement", "list", "pipeline"}:
        return [command for child in node.named_children if child.type != "comment"
                for command in _stage_commands(child)]
    raise AnalysisIncomplete("unsupported pipeline stage")


def _command_redirects(command: Node) -> list[Node]:
    """Retain redirects on a command, enclosing groups, and pipeline endpoints."""
    scopes = []
    current = command
    input_edge = output_edge = True
    group_depth = 0
    while current is not None:
        redirects = []
        for child in current.named_children:
            if child.type not in {"file_redirect", "herestring_redirect", "heredoc_redirect"}:
                continue
            operator = next((n.type for n in child.children if not n.is_named), "")
            if (operator.startswith("<") and input_edge) or (operator.startswith(">") and output_edge):
                redirects.append(child)
        scopes.extend((group_depth, r) for r in redirects)
        parent = current.parent
        if parent is None or parent.type not in {"redirected_statement", "subshell", "compound_statement", "list", "pipeline"}:
            break
        if parent.type == "pipeline":
            stages = [n for n in parent.named_children if n.type != "comment"]
            input_edge &= current == stages[0]
            output_edge &= current == stages[-1]
        elif parent.type in {"subshell", "compound_statement"}:
            group_depth += 1
        current = parent
    # Enclosing group redirections establish inherited descriptors before the
    # child's own redirections. Within each scope, shell order is left to right.
    return [r for _, r in sorted(scopes, key=lambda item: (-item[0], item[1].start_byte))]


def _pipeline(node: Node, result: CommandAnalysis) -> None:
    stages = [_stage_commands(c) for c in node.named_children if c.type != "comment"]
    if not stages or not all(stages):
        raise AnalysisIncomplete("empty pipeline stage")
    try:
        calls = tuple(tuple(result.node_calls[result.location(c)] for c in stage) for stage in stages)
    except KeyError as exc:
        raise AnalysisIncomplete("unresolved pipeline stage") from exc
    # A redirected consumer no longer receives the preceding stage's bytes.
    if not any(c.stdin is not None for stage in calls[1:] for c in stage):
        result.pipelines.append(Pipeline(calls, result.location(node)))
    for stage, nodes in zip(calls[1:], stages[1:], strict=True):
        for call, consumer in zip(stage, nodes, strict=True):
            argv, _ = _argv(consumer)
            if call.stdin is None and _stdin_language(argv) is not None:
                result.fail("pipeline feeds executable text to an interpreter")


def _redirection(node: Node, result: CommandAnalysis) -> Redirection:
    operator = next((n.type for n in node.children if not n.is_named), "")
    descriptor = next((n for n in node.named_children if n.type == "file_descriptor"), None)
    try:
        fd = int(_text(descriptor)) if descriptor else (0 if operator.startswith("<") else 1)
    except ValueError as exc:
        raise AnalysisIncomplete("dynamic redirection descriptor") from exc
    if node.type == "heredoc_redirect":
        target = next((n for n in node.named_children if n.type == "heredoc_body"), None)
        kind = "heredoc"
        value = _text(target) if target else None
    elif node.type == "herestring_redirect":
        target = node.named_children[-1]
        kind, value = "herestring", _literal(target)
    else:
        target = node.child_by_field_name("destination")
        kind = "process" if target and target.type == "process_substitution" else "file"
        value = _literal(target) if target else None
    raw = _text(target) if target else _text(node)
    prefix = node.text[:target.start_byte - node.start_byte].decode() if target else ""
    spelling = prefix + (raw if value is None else value).translate(str.maketrans("|<>", "   "))
    return Redirection(fd, operator, Word(raw, value, "input", result.location(target or node)), kind, result.location(node), spelling)


def _effective_stdin(redirects) -> Redirection | None:
    channels = {}
    for redirect in redirects:
        if redirect.operator in {"<&", ">&"}:
            value = redirect.target.value
            channels[redirect.fd] = channels.get(int(value), redirect) if value and value.isdigit() else redirect
        else:
            channels[redirect.fd] = redirect
    return channels.get(0)


def _shell(source: str, result: CommandAnalysis, depth: int, *, kind: str | None = None) -> None:
    with result.document(source, "shell", kind or ("tool" if result.origin is None else "inline")):
        _shell_body(source, result, depth)


def _shell_body(source: str, result: CommandAnalysis, depth: int) -> None:  # noqa: PLR0912 -- syntax node dispatch
    if depth > MAX_DEPTH:
        raise AnalysisIncomplete("nested execution depth exceeded")
    data = source.encode("utf-8")
    result._bytes -= len(data)
    if result._bytes < 0:
        raise AnalysisIncomplete("command source budget exhausted")
    root = Parser(_LANGUAGE).parse(data).root_node
    if root.has_error:
        result.fail("invalid or unsupported shell syntax")
    stack = [root]
    pipelines = []
    while stack:
        node = stack.pop()
        result.origin = result.location(node)
        result.consume()
        try:
            if node.type == "command":
                argv, literals = _argv(node)
                redirect_nodes = _command_redirects(node)
                argument_nodes = node.children_by_field_name("argument")
                # Some upstream grammar forms misclassify the numeric fd in
                # `0<&0` as an argv operand without reporting a syntax error.
                # Reject disagreement between lexical token adjacency and the
                # parsed descriptor, rather than inferring a script filename.
                if any(a.type == "number" and a.end_byte == r.start_byte
                       and r.child_by_field_name("descriptor") is None
                       for a in argument_nodes for r in redirect_nodes):
                    raise AnalysisIncomplete("ambiguous file descriptor boundary in shell syntax")
                redirects = tuple(_redirection(r, result) for r in redirect_nodes)
                words = [Word(_text(node.child_by_field_name("name")), argv[0], "program", result.location(node.child_by_field_name("name"))),
                         *(Word(_text(n), value, origin=result.location(n)) for n, value in zip(argument_nodes, literals, strict=True))]
                origin = result.origin
                before = len(result.invocations)
                _inspect_argv(argv, literals, result, depth, redirects, words)
                result.origin = origin
                calls = [c for c in result.invocations[before:] if c.origin == origin]
                if calls:
                    result.node_calls[origin] = calls[-1]
                    _inspect_stdin(calls[-1].stdin, argv, result, depth)
            elif node.type == "pipeline":
                pipelines.append(node)
            elif node.type == "heredoc_redirect":
                _heredoc(node, result, depth)
            elif node.type == "comment":
                result.data.append(DataSpan(result.origin, "comment"))
            elif (
                node.type == "function_definition"
                and _text(node.child_by_field_name("name")) == ":"
            ):
                words = [Word(":", ":", "program", result.origin), Word(_text(node), _text(node), "syntax", result.origin)]
                result.invocations.append(Invocation(words[0], (words[1],), result.origin, "shell"))
        except AnalysisIncomplete as exc:
            result.fail(str(exc))
        stack.extend(reversed(node.named_children))
    for pipeline in pipelines:
        result.origin = result.location(pipeline)
        try:
            _pipeline(pipeline, result)
        except AnalysisIncomplete as exc:
            result.fail(str(exc))


def _heredoc(node: Node, result: CommandAnalysis, depth: int) -> None:
    body = next((c for c in node.named_children if c.type == "heredoc_body"), None)
    statement = node.parent
    command = statement.child_by_field_name("body") if statement else None
    if body is None or command is None or command.type != "command":
        raise AnalysisIncomplete("unsupported heredoc receiver")
    argv, _ = _argv(command)
    name = executable_name(argv[0])
    consumers = [c for c in node.named_children if c.type == "pipeline"]
    if consumers:
        # tree-sitter represents `cat <<EOF | sh`'s consumer on the redirect.
        for pipeline in consumers:
            for stage in pipeline.named_children:
                for consumer in _stage_commands(stage):
                    receiver, _ = _argv(consumer)
                    language = _stdin_language(receiver)
                    if language:
                        redirects = tuple(_redirection(r, result) for r in _command_redirects(consumer))
                        if _effective_stdin(redirects) is not None:
                            continue
                        producer = _effective_stdin(tuple(_redirection(r, result) for r in _command_redirects(command)))
                        if producer is None or producer.kind != "heredoc" or producer.target.origin != result.location(body):
                            raise AnalysisIncomplete("pipeline input is not the visible heredoc")
                        previous = result.origin
                        result.origin = result.location(body)
                        _executable_stdin(_text(body), language, result, depth + 1)
                        result.origin = previous
    if _stdin_language(argv) or name in {"cat", "tee"} | _SHELLS or _PYTHON.fullmatch(name):
        # Substitutions in unquoted heredocs remain AST children and are walked
        # by _shell; a following pipeline consumer is checked independently.
        pass
    else:
        raise AnalysisIncomplete("unsupported heredoc consumer")


def _inspect_stdin(stdin: Redirection | None, argv, result: CommandAnalysis, depth: int) -> None:
    language = _stdin_language(argv)
    if stdin is None or language is None:
        return
    if stdin.kind == "process":
        raise AnalysisIncomplete("process substitution supplies executable stdin")
    if stdin.operator in {"<&", ">&"}:
        if stdin.target.value != "-":
            raise AnalysisIncomplete("unresolved executable stdin descriptor")
        return
    if stdin.kind in {"herestring", "heredoc"}:
        if stdin.target.value is None:
            raise AnalysisIncomplete("dynamic executable stdin")
        previous = result.origin
        result.origin = stdin.target.origin
        _executable_stdin(stdin.target.value + "\n", language, result, depth + 1)
        result.origin = previous


def _executable_stdin(source: str, language: str, result: CommandAnalysis, depth: int) -> None:
    if language == "shell":
        _shell(source, result, depth, kind="stdin")
    elif language == "python":
        _python(source, result, depth, kind="stdin")
    else:
        raise AnalysisIncomplete("unsupported executable stdin language")


def _stdin_language(argv: list[str]) -> str | None:
    for _ in range(MAX_DEPTH):
        inner = _unwrap(argv)
        if inner is None:
            break
        if not inner:
            return None
        argv = inner
    else:
        raise AnalysisIncomplete("stdin consumer wrapper depth exceeded")
    name = executable_name(argv[0])
    if name not in _SHELLS | set(_CODE_FLAGS) and not _PYTHON.fullmatch(name):
        return None
    mode, _, _ = _interpreter_source(name, argv[1:])
    if mode != "stdin":
        return None
    return "shell" if name in _SHELLS else ("python" if _PYTHON.fullmatch(name) else "unsupported")


def analyze_command(source: str) -> Analysis:
    """Return visible calls and explicit incomplete-analysis reasons."""
    result = CommandAnalysis()
    _shell(source, result, 0)
    return result.freeze()


def analyze_python(source: str) -> Analysis:
    result = CommandAnalysis()
    _python(source, result, 0)
    return result.freeze()


def analyze_requests(requests: list[tuple[str, str, tuple[str, ...]]]) -> Analysis:
    """All executable fields in an event share source, node and byte budgets."""
    result = CommandAnalysis()
    for language, source, path in requests:
        result.field = path
        (_python if language == "python" else _shell)(source, result, 0)
    return result.freeze()

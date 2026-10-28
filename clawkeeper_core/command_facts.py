"""Language-independent, immutable evidence produced by bounded parsers.

Offsets address UTF-8 bytes in the named source document, including extracted
sources. Nested documents retain the parent operand which supplied their code.
Renderers are compatibility projections, never the parser's input model.
"""

from __future__ import annotations

from dataclasses import dataclass

FACT_VERSION = 1
SUBJECTS = frozenset({"invocation", "program.name", "python.module", "script.path", "python.operation", "path"})


@dataclass(frozen=True)
class Origin:
    source: int
    start: int
    end: int


@dataclass(frozen=True)
class Source:
    language: str
    text: str
    kind: str
    parent: Origin | None = None
    field: tuple[str, ...] = ()


@dataclass(frozen=True)
class Word:
    raw: str
    value: str | None
    role: str = "argument"
    origin: Origin | None = None

    @property
    def literal(self) -> bool:
        return self.value is not None

    @property
    def display(self) -> str:
        return self.raw if self.value is None else self.value


@dataclass(frozen=True)
class Redirection:
    fd: int
    operator: str
    target: Word
    kind: str
    origin: Origin
    spelling: str = ""

    def render(self) -> str:
        if self.spelling:
            return self.spelling
        default = 0 if self.operator.startswith("<") else 1
        descriptor = str(self.fd) if self.fd != default else ""
        target = self.target.display.translate(str.maketrans("|<>", "   "))
        return f"{descriptor}{self.operator} {target}"


@dataclass(frozen=True)
class Invocation:
    program: Word
    arguments: tuple[Word, ...]
    origin: Origin
    language: str
    redirects: tuple[Redirection, ...] = ()
    stdin: Redirection | None = None
    kind: str = "process"

    @property
    def executable(self) -> str:
        return self.program.value or ""

    def render(self, *, learned: bool = False) -> str:
        words = [self.executable]
        for arg in self.arguments:
            if learned and arg.role == "data":
                continue
            if learned and arg.role == "metadata":
                words.append(arg.display.split("=", 1)[0])
                continue
            if learned and arg.role == "code":
                words.append("[CODE]")
            elif arg.role == "syntax":
                words.append(arg.display)
            else:
                value = arg.raw if self.kind == "python.operation" else arg.display
                words.append(value.translate(str.maketrans("|<>", "   ")))
        text = " ".join(words)
        redirects = [r.render() for r in self.redirects if r.kind == "file"]
        return " ".join([text, *redirects])

    @property
    def text(self) -> str:
        return self.render()

    def values(self, subject: str) -> list[str]:
        if subject == "program.name":
            return [self.executable] if self.kind == "process" else []
        if subject == "python.operation":
            return [self.executable.removeprefix("python:")] if self.kind == "python.operation" else []
        if subject == "python.module":
            return [a.value if i and self.arguments[i - 1].value == "-m" else a.value[2:]
                    for i, a in enumerate(self.arguments) if a.role == "module" and a.value is not None]
        if subject == "script.path":
            return [a.value for a in self.arguments if a.role == "script" and a.value is not None]
        if subject == "invocation":
            return [self.render(learned=True)]
        return []


@dataclass(frozen=True)
class Pipeline:
    stages: tuple[tuple[Invocation, ...], ...]
    origin: Origin

    @property
    def executable(self) -> str:
        return self.stages[0][0].executable

    def render(self, *, learned: bool = False) -> str:
        return " | ".join(" ; ".join(c.render(learned=learned) for c in stage) for stage in self.stages)

    @property
    def text(self) -> str:
        return self.render()


@dataclass(frozen=True)
class Diagnostic:
    reason: str
    origin: Origin | None


@dataclass(frozen=True)
class DataSpan:
    origin: Origin
    reason: str


@dataclass(frozen=True)
class Analysis:
    sources: tuple[Source, ...]
    calls: tuple[Invocation, ...]
    pipelines: tuple[Pipeline, ...]
    diagnostics: tuple[Diagnostic, ...]
    data: tuple[DataSpan, ...] = ()

    @property
    def complete(self) -> bool:
        return not self.diagnostics

    @property
    def errors(self) -> tuple[str, ...]:
        return tuple(d.reason for d in self.diagnostics)

    @property
    def invocations(self) -> tuple[Invocation, ...]:
        return tuple(c for c in self.calls if c.kind != "python.operation")

    @property
    def script_operations(self) -> tuple[Invocation, ...]:
        return tuple(c for c in self.calls if c.kind == "python.operation")

    def values(self, subject: str, *, script: bool = False) -> list[str]:
        calls = self.calls if script else self.invocations
        result = [v for call in calls for v in call.values(subject)]
        if subject == "invocation":
            result.extend(p.render(learned=True) for p in self.pipelines)
        return result

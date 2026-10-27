"""Payload mutation engine for gate stage 4 (generalisation testing).

Given an observed malicious request, produce variants that preserve the attack
but change its surface form: encoding, casing, SQL/▸HTML comments, whitespace,
and token chunking. A rule that blocks the observed payload but not its mutants
has memorised a string, not learned the technique (CLAUDE.md FR-V4). The gate
requires a candidate to still block >= a threshold of these mutants.

Mutations are applied to the query string and body of a request record
({method, uri, body, ...}); each returns a new record. Conservative: a mutation
that would change the request's meaning is skipped rather than risk a false
"still blocks".
"""

from __future__ import annotations

import re
import urllib.parse
from typing import Callable


def _split_uri(uri: str) -> tuple[str, str]:
    path, _, query = uri.partition("?")
    return path, query


def _rejoin(path: str, query: str) -> str:
    return f"{path}?{query}" if query else path


# Each mutator takes a raw payload string and returns a mutated one.
def m_identity(s: str) -> str:
    return s


def m_upper_keywords(s: str) -> str:
    for kw in ("select", "union", "or", "and", "from", "where", "script", "alert"):
        s = re.sub(kw, lambda m: m.group(0).upper(), s, flags=re.I)
    return s


def m_mixed_case(s: str) -> str:
    return "".join(c.upper() if i % 2 else c.lower() for i, c in enumerate(s))


def m_url_encode(s: str) -> str:
    return urllib.parse.quote(s, safe="")


def m_double_url_encode(s: str) -> str:
    return urllib.parse.quote(urllib.parse.quote(s, safe=""), safe="")


def m_sql_comments(s: str) -> str:
    # replace spaces with inline comments (classic WAF bypass)
    return s.replace(" ", "/**/")


def m_extra_whitespace(s: str) -> str:
    return re.sub(r"\s+", "  \t ", s)


def m_case_comment(s: str) -> str:
    return m_sql_comments(m_upper_keywords(s))


MUTATORS: dict[str, Callable[[str], str]] = {
    "identity": m_identity,
    "upper_keywords": m_upper_keywords,
    "mixed_case": m_mixed_case,
    "url_encode": m_url_encode,
    "double_url_encode": m_double_url_encode,
    "sql_comments": m_sql_comments,
    "extra_whitespace": m_extra_whitespace,
    "case_comment": m_case_comment,
}


# Path mutators: for payloads that live in the URL PATH (path traversal). The
# query/body mutators above never touch the path, so before these existed a
# traversal rule got zero mutants and passed the mutation stage as "n/a".
def p_encode_slash(s: str) -> str:
    return s.replace("/", "%2f")


def p_double_encode_slash(s: str) -> str:
    return s.replace("/", "%252f")


def p_encode_dots(s: str) -> str:
    return s.replace(".", "%2e")


def p_double_encode_dots(s: str) -> str:
    return s.replace(".", "%252e")


def p_backslash(s: str) -> str:
    return s.replace("../", "..\\")


def p_extra_dots(s: str) -> str:
    return s.replace("../", "....//")


def p_mixed_case_encoding(s: str) -> str:
    return s.replace("/", "%2F").replace(".", "%2E")


PATH_MUTATORS: dict[str, Callable[[str], str]] = {
    "path_encode_slash": p_encode_slash,
    "path_double_encode_slash": p_double_encode_slash,
    "path_encode_dots": p_encode_dots,
    "path_double_encode_dots": p_double_encode_dots,
    "path_backslash": p_backslash,
    "path_extra_dots": p_extra_dots,
    "path_mixed_case_encoding": p_mixed_case_encoding,
}


def _looks_like_traversal(path: str) -> bool:
    low = urllib.parse.unquote(path).lower()
    return "../" in low or "..\\" in low or "/etc/passwd" in low


def _mutate_query(query: str, mut: Callable[[str], str]) -> str:
    """Mutate each parameter VALUE, keep keys and structure."""
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    if not pairs:
        return query
    return urllib.parse.urlencode([(k, mut(v)) for k, v in pairs])


def _mutate_body(body: str, mut: Callable[[str], str]) -> str:
    if not body:
        return body
    # JSON body: mutate string values only.
    try:
        import json
        d = json.loads(body)
        if isinstance(d, dict):
            return json.dumps({k: (mut(v) if isinstance(v, str) else v) for k, v in d.items()})
    except (ValueError, TypeError):
        pass
    # HTML form body (urlencoded): mutate each VALUE and keep the keys and separators, exactly as for a
    # query string. Treating it as one opaque string encoded the "=" and "&" too, which breaks the form
    # (the app no longer sees the parameter), so the "mutant" was not an attack at all; found on DVWA.
    if "=" in body and chr(10) not in body.strip() and not body.lstrip().startswith(("{", "[", "<")):
        q = _mutate_query(body, mut)
        if q != body:
            return q
    return mut(body)


def mutate_request(rec: dict) -> list[dict]:
    """Return one mutated request record per mutator (excluding identity dupes)."""
    path, query = _split_uri(rec.get("uri", ""))
    body = rec.get("body", "") or ""
    out = []
    for name, mut in MUTATORS.items():
        if name == "identity":
            continue
        nq = _mutate_query(query, mut) if query else query
        nb = _mutate_body(body, mut) if body else body
        if nq == query and nb == body:
            continue  # nothing to mutate here
        out.append({**rec, "uri": _rejoin(path, nq), "body": nb, "mutation": name})

    # Path mutations, only for requests whose payload is in the path. Mutate the
    # decoded path once so a payload that arrived encoded is mutated consistently.
    if _looks_like_traversal(path):
        base = urllib.parse.unquote(path)
        for name, mut in PATH_MUTATORS.items():
            np_ = mut(base)
            if np_ != base:
                out.append({**rec, "uri": _rejoin(np_, query), "mutation": name})
    return out


def mutate_corpus(records: list[dict]) -> list[dict]:
    out = []
    for r in records:
        out.extend(mutate_request(r))
    return out

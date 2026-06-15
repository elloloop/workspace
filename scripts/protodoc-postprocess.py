#!/usr/bin/env python3
"""Post-process the generated protoc-gen-doc HTML proto reference:
set a meaningful title and inject a slim nav banner so the standalone page
(hosted at /workspace/proto/) links back to the docs, the raw .proto, and the
Scalar HTTP/JSON view. Idempotent."""
import pathlib
import re
import sys

path = pathlib.Path(sys.argv[1] if len(sys.argv) > 1 else "docs-site/public/proto/index.html")
html = path.read_text()

html = html.replace("<title>Protocol Documentation</title>", "<title>Workspaces · Proto Reference</title>")
html = html.replace(">Protocol Documentation<", ">Workspaces — Proto Reference (workspace.v1)<", 1)

banner = (
    '<div style="background:#0b0b0f;color:#e5e7eb;padding:10px 18px;'
    'font-family:system-ui,-apple-system,sans-serif;font-size:14px;'
    'border-bottom:1px solid #2a2a35;position:sticky;top:0;z-index:10">'
    '<a href="../" style="color:#a78bfa;text-decoration:none">← Workspaces docs</a>'
    '&nbsp;&nbsp;·&nbsp;&nbsp;Generated proto reference'
    '&nbsp;&nbsp;·&nbsp;&nbsp;<a href="workspace-v1.proto" style="color:#a78bfa">raw .proto</a>'
    '&nbsp;&nbsp;·&nbsp;&nbsp;<a href="../api" style="color:#a78bfa">HTTP/JSON (Scalar)</a>'
    "</div>"
)
if "Workspaces docs" not in html:  # idempotent
    html = re.sub(r"(<body[^>]*>)", r"\1" + banner, html, count=1)

path.write_text(html)
print(f"post-processed {path}")

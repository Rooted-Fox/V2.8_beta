"""Parse Swagger/OpenAPI specs and Postman collections into ApiEndpoint objects."""
from __future__ import annotations

import json
from typing import Any, Dict, List, Optional

import yaml

from api_scanner.curl_parser import ApiEndpoint


def _openapi_auth_type(security_schemes: dict, security: list) -> str:
    if not security:
        return "none"
    for req in security:
        for scheme_name in req:
            scheme = security_schemes.get(scheme_name, {})
            t = scheme.get("type", "").lower()
            if t == "http":
                return scheme.get("scheme", "bearer").lower()
            if t == "apikey":
                return "apikey"
            if t == "oauth2":
                return "bearer"
    return "none"


def parse_openapi(content: str) -> List[ApiEndpoint]:
    """Parse a Swagger 2.0 or OpenAPI 3.x spec (JSON or YAML)."""
    endpoints = []
    try:
        try:
            spec = json.loads(content)
        except json.JSONDecodeError:
            spec = yaml.safe_load(content)
    except Exception:
        return endpoints

    # Determine base URL
    if "openapi" in spec:  # OAS 3.x
        servers = spec.get("servers", [{}])
        base_url = servers[0].get("url", "") if servers else ""
        security_schemes = (spec.get("components") or {}).get("securitySchemes", {})
    else:  # Swagger 2.x
        host = spec.get("host", "")
        scheme = (spec.get("schemes") or ["https"])[0]
        basepath = spec.get("basePath", "")
        base_url = f"{scheme}://{host}{basepath}"
        security_schemes = (spec.get("securityDefinitions") or {})

    global_security = spec.get("security", [])
    paths = spec.get("paths", {})

    for path, path_item in paths.items():
        for method in ["get","post","put","patch","delete","options","head"]:
            op = path_item.get(method)
            if not op:
                continue

            ep = ApiEndpoint()
            ep.method = method.upper()
            ep.path = path
            ep.base_url = base_url
            ep.url = f"{base_url}{path}"
            ep.path_params = [p.strip("{}") for p in
                              __import__('re').findall(r'\{([^}]+)\}', path)]

            # Parameters
            for param in (op.get("parameters") or []) + (path_item.get("parameters") or []):
                if param.get("in") == "query":
                    ep.query_params[param["name"]] = [param.get("example", "")]
                elif param.get("in") == "header":
                    ep.headers[param["name"]] = param.get("example", "")

            # Request body (OAS 3.x)
            req_body = op.get("requestBody", {})
            if req_body:
                content_map = req_body.get("content", {})
                for ct, ct_val in content_map.items():
                    ep.content_type = ct
                    schema = ct_val.get("schema", {})
                    ep.body = _schema_to_example(schema)
                    break

            # Auth
            op_security = op.get("security", global_security)
            ep.auth_type = _openapi_auth_type(security_schemes, op_security)

            endpoints.append(ep)

    return endpoints


def _schema_to_example(schema: dict, depth: int = 0) -> Any:
    """Generate a realistic example value from a JSON schema."""
    if depth > 3 or not schema:
        return None
    t = schema.get("type", "object")
    if "example" in schema:
        return schema["example"]
    if "properties" in schema or t == "object":
        result = {}
        for k, v in (schema.get("properties") or {}).items():
            result[k] = _schema_to_example(v, depth + 1)
        return result
    if t == "array":
        item = _schema_to_example(schema.get("items", {}), depth + 1)
        return [item] if item is not None else []
    if t == "integer":
        return schema.get("example", 1)
    if t == "number":
        return schema.get("example", 1.0)
    if t == "boolean":
        return True
    if t == "string":
        fmt = schema.get("format", "")
        if fmt == "email":
            return "user@example.com"
        if fmt == "date-time":
            return "2024-01-01T00:00:00Z"
        if fmt == "uuid":
            return "00000000-0000-0000-0000-000000000001"
        return schema.get("example", "string")
    return None


def parse_postman(content: str) -> List[ApiEndpoint]:
    """Parse a Postman collection v2.0 or v2.1 export."""
    endpoints = []
    try:
        collection = json.loads(content)
    except (json.JSONDecodeError, Exception):
        return endpoints

    def _extract_items(items):
        for item in items:
            if "item" in item:
                _extract_items(item["item"])  # folder — recurse
            elif "request" in item:
                req = item["request"]
                ep = ApiEndpoint()
                ep.method = (req.get("method") or "GET").upper()

                # URL
                url_obj = req.get("url", {})
                if isinstance(url_obj, str):
                    ep.url = url_obj
                else:
                    raw = url_obj.get("raw", "")
                    ep.url = raw
                    ep.base_url = f"{url_obj.get('protocol','https')}://{'.'.join(url_obj.get('host',[]))}"
                    ep.path = "/" + "/".join(url_obj.get("path", []))
                    ep.path_params = [p.strip(":") for p in url_obj.get("path", [])
                                      if p.startswith(":") or (p.startswith("{") and p.endswith("}"))]
                    for qp in url_obj.get("query", []):
                        if not qp.get("disabled"):
                            ep.query_params[qp["key"]] = [qp.get("value", "")]

                # Headers
                for h in req.get("header", []):
                    if not h.get("disabled"):
                        ep.headers[h["key"]] = h.get("value", "")

                # Body
                body = req.get("body", {})
                if body:
                    mode = body.get("mode", "")
                    if mode == "raw":
                        ep.body_raw = body.get("raw", "")
                        try:
                            ep.body = json.loads(ep.body_raw)
                        except Exception:
                            pass
                    elif mode == "urlencoded":
                        ep.body = {p["key"]: p.get("value","") for p in body.get("urlencoded", []) if not p.get("disabled")}
                    elif mode == "formdata":
                        ep.body = {p["key"]: p.get("value","") for p in body.get("formdata", []) if not p.get("disabled")}

                ep.content_type = ep.headers.get("Content-Type",
                                                   ep.headers.get("content-type", ""))
                from api_scanner.curl_parser import _detect_auth
                ep.auth_type, ep.auth_value = _detect_auth(ep.headers)
                endpoints.append(ep)

    _extract_items(collection.get("item", []))
    return endpoints


def parse_file(content: str, filename: str = "") -> List[ApiEndpoint]:
    """Auto-detect format and parse."""
    fname = filename.lower()
    if fname.endswith(".json"):
        parsed = json.loads(content)
        if "item" in parsed or "info" in parsed:
            return parse_postman(content)
        return parse_openapi(content)
    elif fname.endswith((".yaml", ".yml")):
        return parse_openapi(content)
    # Guess from content
    try:
        parsed = json.loads(content)
        if "item" in parsed or "info" in parsed:
            return parse_postman(content)
        return parse_openapi(content)
    except json.JSONDecodeError:
        return parse_openapi(content)  # try YAML

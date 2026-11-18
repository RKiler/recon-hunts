"""Same-origin, authenticated dashboard facade for the private BugHunter socket."""

from __future__ import annotations

import http.client
import json
import os
import re
import socket
from urllib.parse import urlencode

from flask import Response, abort, jsonify, render_template, request


_TAIL = re.compile(r"[A-Za-z0-9_/-]{1,180}\Z")
_QUERY_KEYS = frozenset({"target", "limit", "cursor", "identity", "session", "method",
                         "status", "source", "scope", "category", "type", "tenant", "cleanup", "archived",
                         "hunt_id", "state", "operation_id", "offset", "baseline_id",
                         "current_id", "run_id"})
_SECTIONS = frozenset({"overview", "targets", "hunt", "accounts", "sessions", "traffic",
                       "scope", "burp", "hypotheses", "approvals", "skills", "plans", "runs",
                       "validations", "findings", "objects", "authorization", "domxss",
                       "postmessage", "exposure", "behaviour", "api", "research", "planner",
                       "campaigns", "deltas", "evaluation",
                       "reports", "operations"})
_SOCKET = "/run/bughunter-agent/control.sock"


class UnixHTTPConnection(http.client.HTTPConnection):
    def __init__(self, path: str, timeout: float = 3.0) -> None:
        super().__init__("localhost", timeout=timeout)
        self.path = path

    def connect(self) -> None:
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.settimeout(self.timeout)
        self.sock.connect(self.path)


def install_hackbot_routes(app, *, authorized, csrf_token, require_csrf, auth_enabled,
                           socket_path: str | None = None,
                           hunt_ui_enabled: bool = False) -> None:
    """Register the UI and a narrow JSON proxy. Never forwards client credentials."""

    def gate():
        if not auth_enabled():
            return jsonify(error="dashboard_auth_required"), 503
        if not authorized():
            return jsonify(error="authentication_required", login_url="/login"), 401
        return None

    @app.get("/hackbot")
    @app.get("/hackbot/")
    @app.get("/hackbot/<section>")
    def hackbot_panel(section="overview"):
        problem = gate()
        if problem:
            return problem
        if section not in _SECTIONS:
            abort(404)
        if section == "hunt" and not hunt_ui_enabled:
            abort(404)
        return render_template("hackbot_panel.html", section=section,
                               csrf_token=csrf_token(), hunt_ui_enabled=hunt_ui_enabled)

    @app.route("/api/hackbot/<path:tail>", methods=["GET", "POST", "DELETE"])
    def hackbot_api(tail: str):
        problem = gate()
        if problem:
            return problem
        if not _TAIL.fullmatch(tail) or ".." in tail or "//" in tail:
            return jsonify(error="invalid_route"), 400
        if re.match(r"targets/[^/]+/hunt(?:/|$)", tail) and not (
                request.method in {"GET", "POST"} and
                re.fullmatch(r"targets/[a-z][a-z0-9_-]{0,63}/hunt", tail)):
            return jsonify(error="invalid_route"), 400
        if tail.endswith("/hunt") and request.method == "POST" and not hunt_ui_enabled:
            return jsonify(error="hunt_not_ready"), 409
        if tail.startswith("operations"):
            allowed = (tail in {"operations", "operations/maintenance"}
                       if request.method == "GET" else tail == "operations/maintenance")
            if not allowed:
                return jsonify(error="invalid_route"), 400
        if "/behaviour" in tail:
            package = r"[a-z][a-z0-9_-]{0,63}"
            run = r"LEARN-[0-9a-f]{32}"
            allowed = (
                re.fullmatch(rf"targets/{package}/behaviour(?:/(?:coverage|features|workflows|matrix|gaps))?", tail)
                or re.fullmatch(rf"targets/{package}/behaviour/runs/{run}", tail)
            ) if request.method == "GET" else (
                re.fullmatch(rf"targets/{package}/behaviour(?:/(?:refresh|expectations))?", tail)
                or re.fullmatch(rf"targets/{package}/behaviour/runs/{run}/cancel", tail)
            )
            if not allowed:
                return jsonify(error="invalid_route"), 400
        if tail.startswith("postmessage/"):
            package = r"[A-Za-z0-9_-]+"
            candidate = r"MSG-[0-9a-f]{32}"
            allowed = (
                re.fullmatch(rf"postmessage/{package}/(?:inventory|metrics|candidates)", tail)
                or re.fullmatch(rf"postmessage/{package}/candidates/{candidate}(?:/runtime)?", tail)
            ) if request.method == "GET" else (
                re.fullmatch(rf"postmessage/{package}/analyze", tail)
                or re.fullmatch(rf"postmessage/{package}/candidates/{candidate}/(?:route|prepare|bind-plan)", tail)
            )
            if not allowed:
                return jsonify(error="invalid_route"), 400
        if tail.startswith("exposure/"):
            package = r"[A-Za-z0-9_-]+"
            candidate = r"EXP-[0-9a-f]{32}"
            allowed = (
                re.fullmatch(rf"exposure/{package}/(?:candidates|metrics|artifacts|captures|field-exchanges)", tail)
                or re.fullmatch(rf"exposure/{package}/candidates/{candidate}", tail)
            ) if request.method == "GET" else (
                re.fullmatch(rf"exposure/{package}/(?:discover|analyze|analyze-response|analyze-field)", tail)
                or re.fullmatch(rf"exposure/{package}/candidates/{candidate}/(?:prepare|bind-read|bind-field)", tail)
            )
            if not allowed:
                return jsonify(error="invalid_route"), 400
        if tail.startswith("api/"):
            package = r"[A-Za-z0-9_-]+"
            operation = r"APIO-[0-9a-f]{32}"
            candidate = r"APIC-[0-9a-f]{32}"
            allowed = (
                re.fullmatch(rf"api/{package}/(?:coverage|operations|candidates)", tail)
                or re.fullmatch(rf"api/{package}/operations/{operation}", tail)
                or re.fullmatch(rf"api/{package}/candidates/{candidate}", tail)
            ) if request.method == "GET" else (
                re.fullmatch(rf"api/{package}/analyze", tail)
                or re.fullmatch(rf"api/{package}/candidates/{candidate}/(?:prepare|start|advance)", tail)
            )
            if not allowed:
                return jsonify(error="invalid_route"), 400
        if tail.startswith("research/"):
            package = r"[a-z][a-z0-9_-]{0,63}"
            research_request = r"RREQ-[0-9a-f]{32}"
            brief = r"RBRF-[0-9a-f]{32}"
            allowed = (
                re.fullmatch(rf"research/{package}/(?:gaps|requests|metrics)", tail)
                or re.fullmatch(rf"research/{package}/requests/{research_request}", tail)
                or re.fullmatch(rf"research/{package}/briefs/{brief}", tail)
            ) if request.method == "GET" else (
                re.fullmatch(rf"research/{package}/requests", tail)
                or re.fullmatch(rf"research/{package}/requests/{research_request}/cancel", tail)
                or re.fullmatch(rf"research/{package}/briefs/{brief}/refresh", tail)
            )
            if not allowed:
                return jsonify(error="invalid_route"), 400
        if tail.startswith("planner/"):
            package = r"[a-z][a-z0-9_-]{0,63}"
            run = r"PLRUN-[0-9a-f]{32}"
            candidate = r"PLCAND-[0-9a-f]{32}"
            allowed = (
                re.fullmatch(rf"planner/{package}/runs(?:/{run})?", tail)
                or re.fullmatch(rf"planner/{package}/runs/{run}/(?:candidates|tasks)", tail)
                or re.fullmatch(rf"planner/{package}/runs/{run}/candidates/{candidate}/relationships", tail)
            ) if request.method == "GET" else (
                re.fullmatch(rf"planner/{package}/runs", tail)
                or re.fullmatch(rf"planner/{package}/runs/{run}/(?:advance|pause|resume|cancel)", tail)
                or re.fullmatch(rf"planner/{package}/runs/{run}/candidates/{candidate}/override", tail)
            )
            if not allowed:
                return jsonify(error="invalid_route"), 400
        if tail.startswith("campaigns"):
            campaign = r"CMP-[0-9a-f]{32}"
            allowed = (
                tail == "campaigns" or re.fullmatch(rf"campaigns/{campaign}", tail)
            ) if request.method == "GET" else (
                tail == "campaigns" or
                re.fullmatch(rf"campaigns/{campaign}/(?:pause|resume|cancel|archive)", tail)
            )
            if not allowed:
                return jsonify(error="invalid_route"), 400
        if tail.startswith("continuous"):
            package = r"[a-z][a-z0-9_-]{0,63}"
            allowed = (
                tail == "continuous/status" or
                re.fullmatch(rf"continuous/targets/{package}", tail)
            ) if request.method == "GET" else (
                re.fullmatch(rf"continuous/targets/{package}/(?:settings|pause|resume|check)", tail)
            )
            if not allowed:
                return jsonify(error="invalid_route"), 400
        if tail.startswith("deltas"):
            delta = r"DELTA-[0-9a-f]{32}"
            allowed = (
                tail == "deltas" or re.fullmatch(rf"deltas/{delta}", tail)
            ) if request.method == "GET" else (
                re.fullmatch(rf"deltas/{delta}/campaigns", tail)
            )
            if not allowed:
                return jsonify(error="invalid_route"), 400
        if tail.startswith("reports"):
            report = r"REPORT-[0-9a-f]{32}"
            allowed = (tail == "reports" or
                       re.fullmatch(rf"reports/{report}(?:/download)?", tail)) if request.method == "GET" else (
                       re.fullmatch(rf"reports/{report}/edit", tail))
            if not allowed:
                return jsonify(error="invalid_route"), 400
        if tail.startswith("notifications"):
            allowed = tail in {"notifications", "notifications/status"} if request.method == "GET" else (
                tail == "notifications/test")
            if not allowed:
                return jsonify(error="invalid_route"), 400
        if tail.startswith("evaluation"):
            run = r"BENCH-[0-9a-f]{32}"
            allowed = request.method == "GET" and (
                tail in {"evaluation/suites", "evaluation/runs", "evaluation/compare",
                         "evaluation/readiness"} or
                re.fullmatch(rf"evaluation/runs/{run}(?:/cases)?", tail))
            if not allowed:
                return jsonify(error="invalid_route"), 400
            query_keys = {
                "evaluation/suites": frozenset(),
                "evaluation/runs": frozenset({"limit"}),
                "evaluation/compare": frozenset({"baseline_id", "current_id"}),
                "evaluation/readiness": frozenset({"run_id"}),
            }.get(tail, frozenset({"limit", "offset"}) if tail.endswith("/cases") else frozenset())
            if (any(key not in query_keys or len(request.args.getlist(key)) != 1
                    for key in request.args) or
                    any(not re.fullmatch(run, request.args[key])
                        for key in ("baseline_id", "current_id", "run_id") if key in request.args)):
                return jsonify(error="invalid_query"), 400
        if any(key not in _QUERY_KEYS for key in request.args):
            return jsonify(error="invalid_query"), 400
        if request.method == "DELETE" and not (
                re.fullmatch(r"browser/sessions/BSESSION-[0-9a-f]{32}", tail) or
                re.fullmatch(r"targets/[a-z][a-z0-9_-]{0,63}/accounts/[a-z][a-z0-9_-]{0,63}", tail) or
                re.fullmatch(r"targets/[a-z][a-z0-9_-]{0,63}", tail)):
            return jsonify(error="invalid_route"), 400
        if "operation_id" in request.args and (
                request.method != "GET" or
                not re.fullmatch(r"api/[A-Za-z0-9_-]+/candidates", tail) or
                not re.fullmatch(r"APIO-[0-9a-f]{32}", request.args["operation_id"])):
            return jsonify(error="invalid_query"), 400
        if request.method in {"POST", "DELETE"}:
            require_csrf()
        if request.method in {"POST", "DELETE"}:
            setup_payload = tail == "targets" or bool(re.fullmatch(
                r"targets/[a-z][a-z0-9_-]{0,63}/accounts", tail))
            body_limit = 70_000 if (setup_payload or re.fullmatch(
                r"reports/REPORT-[0-9a-f]{32}/edit", tail)) else 16_384
            if not request.is_json or request.content_length is None or request.content_length > body_limit:
                return jsonify(error="invalid_body"), 400
            value = request.get_json(silent=True)
            if not isinstance(value, dict):
                return jsonify(error="invalid_body"), 400
            body = json.dumps(value, separators=(",", ":")).encode("utf-8")
            if len(body) > body_limit:
                return jsonify(error="invalid_body"), 400
        else:
            body = None
        query = urlencode(request.args.to_dict(flat=True))
        path = "/v1/" + tail + ("?" + query if query else "")
        sock_path = socket_path or os.environ.get("HACKBOT_SOCKET", _SOCKET)
        if socket_path is None and not sock_path.startswith("/run/bughunter-agent/"):
            return jsonify(error="service_unavailable"), 503
        long_operation = request.method == "POST" and (
            tail.endswith("/profile") or
            bool(re.fullmatch(r"authorization/[A-Za-z0-9_-]+/(?:hunts|candidates/[A-Za-z0-9_-]+/(?:start|advance))", tail)) or
            bool(re.fullmatch(r"api/[A-Za-z0-9_-]+/(?:analyze|candidates/APIC-[0-9a-f]{32}/(?:start|advance))", tail)) or
            bool(re.fullmatch(r"objects(?:/TESTOBJ-[0-9a-f]{32}/(?:create|cleanup))?", tail)) or
            bool(re.fullmatch(r"(?:domxss|postmessage|exposure)/[A-Za-z0-9_-]+/(?:analyze|analyze-response|analyze-field|discover)", tail)) or
            bool(re.fullmatch(r"planner/[a-z][a-z0-9_-]{0,63}/runs(?:/PLRUN-[0-9a-f]{32}/(?:advance|resume))?", tail)) or
            bool(re.fullmatch(r"campaigns(?:/CMP-[0-9a-f]{32}/(?:pause|resume|cancel))?", tail)) or
            bool(re.fullmatch(r"continuous/targets/[a-z][a-z0-9_-]{0,63}/check", tail)) or
            bool(re.fullmatch(r"deltas/DELTA-[0-9a-f]{32}/campaigns", tail)) or
            bool(re.fullmatch(r"runs/RUN-[0-9a-f]{32}/(?:advance|validate)", tail)))
        connection = UnixHTTPConnection(sock_path, timeout=45.0 if long_operation else
                                        15.0 if request.method == "GET" else 3.0)
        report_download = request.method == "GET" and bool(
            re.fullmatch(r"reports/REPORT-[0-9a-f]{32}/download", tail))
        try:
            connection.request(request.method, path, body=body,
                               headers={"Host": "localhost", "Accept": "text/plain" if report_download else "application/json",
                                        **({"Content-Type": "application/json"} if body is not None else {})})
            upstream = connection.getresponse()
            if upstream.status < 100 or upstream.status > 599:
                return jsonify(error="service_unavailable"), 503
            response_limit = 65_536 if report_download and upstream.status == 200 else 524_288
            response_body = upstream.read(response_limit + 1)
            if len(response_body) > response_limit:
                return jsonify(error="service_unavailable"), 503
            if report_download and upstream.status == 200:
                if "text/plain" not in upstream.getheader("Content-Type", ""):
                    return jsonify(error="service_unavailable"), 503
                report_id = tail.split("/")[1]
                response = Response(response_body, status=200, content_type="text/plain; charset=utf-8")
                response.headers["Content-Disposition"] = f'attachment; filename="{report_id}.md"'
                response.headers["X-Content-Type-Options"] = "nosniff"
                return response
            if "application/json" not in upstream.getheader("Content-Type", ""):
                return jsonify(error="service_unavailable"), 503
            json.loads(response_body)
            return Response(response_body, status=upstream.status, mimetype="application/json")
        except (OSError, TimeoutError, http.client.HTTPException, ValueError, json.JSONDecodeError):
            return jsonify(error="service_unavailable"), 503
        finally:
            connection.close()

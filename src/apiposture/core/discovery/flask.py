"""Flask endpoint discoverer."""

import ast
from collections.abc import Iterator
from pathlib import Path

from apiposture.core.analysis.source_loader import ASTHelpers, ParsedSource
from apiposture.core.authorization.flask_auth import FlaskAuthExtractor
from apiposture.core.discovery.base import EndpointDiscoverer
from apiposture.core.models.authorization import AuthorizationInfo
from apiposture.core.models.endpoint import Endpoint
from apiposture.core.models.enums import EndpointType, Framework, HttpMethod

# Flask route decorator patterns
FLASK_ROUTE_DECORATORS = {"route", "get", "post", "put", "delete", "patch"}

# Flask import indicators
FLASK_IMPORTS = {"flask", "Flask", "Blueprint"}


class FlaskEndpointDiscoverer(EndpointDiscoverer):
    """Discovers endpoints in Flask applications."""

    def __init__(self) -> None:
        self.auth_extractor = FlaskAuthExtractor()

    @property
    def framework(self) -> Framework:
        return Framework.FLASK

    def can_handle(self, source: ParsedSource) -> bool:
        """Check if the source imports Flask."""
        for node in ast.walk(source.tree):
            if isinstance(node, ast.Import):
                for alias in node.names:
                    if alias.name in FLASK_IMPORTS or alias.name.startswith("flask"):
                        return True
            elif isinstance(node, ast.ImportFrom):
                if node.module and (node.module == "flask" or node.module.startswith("flask")):
                    return True
        return False

    def discover(self, source: ParsedSource, file_path: Path) -> Iterator[Endpoint]:
        """Discover Flask endpoints."""
        # Track blueprint variables and their prefixes
        blueprints = self._find_blueprints(source)

        # Find all decorated functions
        for node in ast.walk(source.tree):
            if isinstance(node, ast.FunctionDef):
                yield from self._process_function(node, source, file_path, blueprints)

    def _find_blueprints(self, source: ParsedSource) -> dict[str, dict[str, str]]:
        """
        Find Blueprint instantiations and their configurations.

        Returns dict mapping variable name to blueprint config (url_prefix).
        """
        blueprints: dict[str, dict[str, str]] = {}

        for node in ast.walk(source.tree):
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Name) and isinstance(node.value, ast.Call):
                        call_name = ASTHelpers.get_call_name(node.value)
                        if call_name and call_name.endswith("Blueprint"):
                            blueprints[target.id] = self._extract_blueprint_config(node.value)

        return blueprints

    def _extract_blueprint_config(self, call: ast.Call) -> dict[str, str]:
        """Extract configuration from a Blueprint() call."""
        config: dict[str, str] = {
            "url_prefix": "",
        }

        # url_prefix can be a keyword argument
        prefix_arg = ASTHelpers.find_keyword_arg(call, "url_prefix")
        if prefix_arg:
            prefix = ASTHelpers.get_string_value(prefix_arg)
            if prefix:
                config["url_prefix"] = prefix

        return config

    def _process_function(
        self,
        node: ast.FunctionDef,
        source: ParsedSource,
        file_path: Path,
        blueprints: dict[str, dict[str, str]],
    ) -> Iterator[Endpoint]:
        """Process a function definition for route decorators."""
        # Extract all route decorators and auth decorators
        route_decorators: list[ast.Call] = []
        auth_info = AuthorizationInfo(source="function")

        for decorator in node.decorator_list:
            # Check if it's a route decorator
            if isinstance(decorator, ast.Call):
                dec_name = ASTHelpers.get_decorator_name(decorator)
                if dec_name:
                    parts = dec_name.split(".")
                    method_name = parts[-1].lower()
                    if method_name in FLASK_ROUTE_DECORATORS:
                        route_decorators.append(decorator)
                        continue

            # Extract auth info from this decorator
            dec_auth = self.auth_extractor.extract_from_decorator(decorator)
            if dec_auth.requires_auth or dec_auth.allows_anonymous:
                auth_info = auth_info.merge(dec_auth)

        # Create endpoints for each route decorator
        for route_dec in route_decorators:
            endpoint = self._extract_endpoint_from_decorator(
                node, route_dec, file_path, blueprints, auth_info
            )
            if endpoint:
                yield endpoint

    def _extract_endpoint_from_decorator(
        self,
        node: ast.FunctionDef,
        decorator: ast.Call,
        file_path: Path,
        blueprints: dict[str, dict[str, str]],
        auth_info: AuthorizationInfo,
    ) -> Endpoint | None:
        """Extract endpoint info from a route decorator."""
        decorator_name = ASTHelpers.get_decorator_name(decorator)
        if not decorator_name:
            return None

        parts = decorator_name.split(".")
        method_name = parts[-1].lower()

        # Determine HTTP methods
        methods: list[HttpMethod]
        if method_name == "route":
            # Get methods from keyword argument
            methods_arg = ASTHelpers.find_keyword_arg(decorator, "methods")
            if methods_arg:
                method_strs = ASTHelpers.get_list_of_strings(methods_arg)
                methods = [
                    HttpMethod(m.upper())
                    for m in method_strs
                    if m.upper() in HttpMethod.__members__
                ]
            else:
                methods = [HttpMethod.GET]  # Default
        elif method_name == "get":
            methods = [HttpMethod.GET]
        elif method_name == "post":
            methods = [HttpMethod.POST]
        elif method_name == "put":
            methods = [HttpMethod.PUT]
        elif method_name == "delete":
            methods = [HttpMethod.DELETE]
        elif method_name == "patch":
            methods = [HttpMethod.PATCH]
        else:
            return None

        # Extract route path
        route = "/"
        if decorator.args:
            route_arg = ASTHelpers.get_string_value(decorator.args[0])
            if route_arg:
                route = route_arg

        # Determine blueprint prefix
        router_prefix = ""
        if len(parts) > 1:
            blueprint_var = parts[-2]
            if blueprint_var in blueprints:
                router_prefix = blueprints[blueprint_var].get("url_prefix", "")

        return Endpoint(
            route=route,
            methods=methods,
            file_path=file_path,
            line_number=node.lineno,
            framework=Framework.FLASK,
            endpoint_type=EndpointType.FUNCTION,
            function_name=node.name,
            authorization=auth_info,
            router_prefix=router_prefix,
        )

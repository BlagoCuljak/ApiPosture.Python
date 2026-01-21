"""Tests for Flask endpoint discoverer."""

from pathlib import Path

import pytest

from apiposture.core.discovery.flask import FlaskEndpointDiscoverer
from apiposture.core.models.enums import Framework, HttpMethod


@pytest.fixture
def discoverer():
    """Create a Flask discoverer."""
    return FlaskEndpointDiscoverer()


class TestFlaskDiscoverer:
    """Tests for FlaskEndpointDiscoverer."""

    def test_can_handle_flask_import(self, discoverer, parse_code):
        """Test that discoverer recognizes Flask imports."""
        code = """
from flask import Flask

app = Flask(__name__)
"""
        source = parse_code(code)
        assert discoverer.can_handle(source)

    def test_cannot_handle_non_flask(self, discoverer, parse_code):
        """Test that discoverer rejects non-Flask code."""
        code = """
from fastapi import FastAPI

app = FastAPI()
"""
        source = parse_code(code)
        assert not discoverer.can_handle(source)

    def test_discover_route_endpoint(self, discoverer, parse_code):
        """Test discovering a route endpoint."""
        code = """
from flask import Flask

app = Flask(__name__)

@app.route("/users")
def get_users():
    return []
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].route == "/users"
        assert endpoints[0].methods == [HttpMethod.GET]
        assert endpoints[0].function_name == "get_users"
        assert endpoints[0].framework == Framework.FLASK

    def test_discover_route_with_methods(self, discoverer, parse_code):
        """Test discovering a route with explicit methods."""
        code = """
from flask import Flask

app = Flask(__name__)

@app.route("/users", methods=["GET", "POST"])
def users():
    return []
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert set(endpoints[0].methods) == {HttpMethod.GET, HttpMethod.POST}

    def test_discover_get_shorthand(self, discoverer, parse_code):
        """Test discovering @app.get shorthand."""
        code = """
from flask import Flask

app = Flask(__name__)

@app.get("/users")
def get_users():
    return []
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].methods == [HttpMethod.GET]

    def test_discover_post_shorthand(self, discoverer, parse_code):
        """Test discovering @app.post shorthand."""
        code = """
from flask import Flask

app = Flask(__name__)

@app.post("/users")
def create_user():
    return {}
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].methods == [HttpMethod.POST]

    def test_discover_with_login_required(self, discoverer, parse_code):
        """Test discovering endpoint with login_required decorator."""
        code = """
from flask import Flask
from flask_login import login_required

app = Flask(__name__)

@app.route("/profile")
@login_required
def get_profile():
    return {}
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].authorization.requires_auth

    def test_discover_with_roles_required(self, discoverer, parse_code):
        """Test discovering endpoint with roles_required decorator."""
        code = """
from flask import Flask

app = Flask(__name__)

def roles_required(*roles):
    def decorator(f):
        return f
    return decorator

@app.route("/admin")
@roles_required("admin", "moderator")
def admin():
    return {}
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].authorization.requires_auth
        assert "admin" in endpoints[0].authorization.roles
        assert "moderator" in endpoints[0].authorization.roles

    def test_discover_blueprint_with_prefix(self, discoverer, parse_code):
        """Test discovering endpoints from blueprint with prefix."""
        code = """
from flask import Blueprint

bp = Blueprint("api", __name__, url_prefix="/api/v1")

@bp.route("/items")
def get_items():
    return []
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 1
        assert endpoints[0].route == "/items"
        assert endpoints[0].router_prefix == "/api/v1"
        assert endpoints[0].full_route == "/api/v1/items"

    def test_discover_multiple_endpoints(self, discoverer, parse_code):
        """Test discovering multiple endpoints."""
        code = """
from flask import Flask

app = Flask(__name__)

@app.route("/")
def index():
    return "Hello"

@app.route("/users", methods=["GET"])
def get_users():
    return []

@app.route("/users", methods=["POST"])
def create_user():
    return {}
"""
        source = parse_code(code)
        endpoints = list(discoverer.discover(source, Path("test.py")))

        assert len(endpoints) == 3

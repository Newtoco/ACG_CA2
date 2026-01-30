"""
Routes package - Contains all Flask blueprints
"""
from .auth import auth_bp
from .vault import vault_bp

__all__ = ['auth_bp', 'vault_bp']

"""Public blog subscription blueprint.

Public endpoints (no auth):
  POST /api/blog/subscribe        — subscribe an email (Turnstile-gated, rate-limited)
  GET  /api/blog/unsubscribe/<token>  — one-click unsubscribe via signed token

Admin endpoints (superadmin only):
  POST /api/admin/blog/send       — push an article notification to all active subscribers
  GET  /api/admin/blog/subscribers — list subscribers (paginated)
  GET  /api/admin/blog/article-sent/<slug> — counts of who's already received a given article
"""

from .routes import blog_bp, blog_admin_bp

__all__ = ["blog_bp", "blog_admin_bp"]

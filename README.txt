INSYNC OPERATIONS – LIVE DEPLOYMENT PACKAGE

Ownership / branding:
- Software Managed by PK Hospitality
- Property Operations by InSync Hospitality
- Super Admin owner: PK Hospitality
- AI Admin: Super Admin only, confirmation required

SECURITY:
- Keep OPENAI_API_KEY only on the server.
- Set PK_HOSPITALITY_ADMIN_TOKEN to a long random secret.
- Do not put either secret into the HTML or Git repository.
- For production, put this server behind HTTPS and your normal identity/access gateway.

WINDOWS CMD example:
  set OPENAI_API_KEY=YOUR_OPENAI_KEY
  set PK_HOSPITALITY_ADMIN_TOKEN=YOUR_LONG_RANDOM_ADMIN_TOKEN
  set PORT=8080
  node server.js

Then open:
  http://localhost:8080/

The server exposes:
  GET  /health
  POST /api/admin-ai
  POST /api/admin-ai/apply
  GET  /api/admin-rules
  GET  /api/admin-audit

Important:
The HTML remains a browser application and existing operational data is still localStorage-based. A real multi-property production deployment should move operational data and authentication to a shared database/backend before multiple properties use it concurrently.

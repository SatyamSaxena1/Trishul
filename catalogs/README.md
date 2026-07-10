# Framework catalogs

Framework content is not hard-coded or silently downloaded. A reviewed catalog uses this JSON shape:

```json
{
  "framework": "OWASP ASVS",
  "version": "verified-current-version",
  "requirements": [
    {
      "control_id": "verified identifier",
      "title": "Control title",
      "requirement": "Licensed requirement text"
    }
  ]
}
```

Verify the official version, source, licensing, and selected MVP scope, then run:

```text
python manage.py import_framework --tenant TENANT --file catalog.json --source-url OFFICIAL_URL --approve
```

The original bytes are hashed. An existing framework/version cannot be replaced with different content.


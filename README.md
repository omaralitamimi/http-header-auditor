# HTTP Security Header Auditor

Reviews a saved HTTP response-header file against a basic browser-hardening baseline. The tool stays offline, so it is safe for portfolio demonstrations.

```bash
python main.py sample_headers.txt
python -m unittest -v
```

Missing headers are configuration review items, not proof of a vulnerability. Production recommendations must consider application behavior and deployment context.

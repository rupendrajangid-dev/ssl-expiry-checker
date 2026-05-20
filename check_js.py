import re

with open("ssl_monitor.py", "r", encoding="utf-8") as f:
    content = f.read()

# Find the JS script block for the dashboard.
# We know it starts with `<!-- AJAX Dashboard Core Logic Scripts -->` or `<script>` after line 3000.
# Let's find all script blocks.
matches = list(re.finditer(r"<script>(.*?)</script>", content, re.DOTALL))
print(f"Found {len(matches)} script blocks.")

for i, match in enumerate(matches):
    js_code = match.group(1)
    filename = f"scratch_js_{i}.js"
    with open(filename, "w", encoding="utf-8") as jf:
        jf.write(js_code)
    print(f"Wrote {filename} ({len(js_code)} bytes).")

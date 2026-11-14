test:
	ruby tests/test_audit.rb

sample:
	mkdir -p docs site
	ruby bin/nginx-audit examples/configs > docs/sample-output.txt; true
	ruby bin/nginx-audit examples/configs --tsv > docs/sample-output.tsv; true
	python3 scripts/site.py docs/sample-output.tsv site/index.html "nginx-audit" "Audits nginx configuration files for weak TLS, information leaks, off-by-slash alias traversal and missing headers. Ruby." "Synthetic configs, not from a real host."

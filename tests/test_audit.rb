# frozen_string_literal: true

require 'minitest/autorun'
require 'open3'
require_relative '../lib/nginx_audit'

class ParserTest < Minitest::Test
  def test_simple_directive
    r = NginxAudit.parse("worker_processes 4;\n")
    assert_equal 1, r.children.size
    assert_equal 'worker_processes', r.children[0].name
    assert_equal ['4'], r.children[0].args
    assert_equal 1, r.children[0].line
  end

  def test_nested_blocks_and_lines
    r = NginxAudit.parse("http {\n  server {\n    listen 80;\n  }\n}\n")
    http = r.children[0]
    assert http.block?
    server = http.children[0]
    assert_equal 2, server.line
    assert_equal 3, server.children[0].line
    assert_same http, server.parent
  end

  def test_comments_are_ignored
    r = NginxAudit.parse("# a { b ;\nlisten 80; # trailing ; {\n")
    assert_equal 1, r.children.size
    assert_equal 2, r.children[0].line
  end

  def test_quoted_values_keep_punctuation
    r = NginxAudit.parse(%(return 200 "a;b{c}";\nadd_header X 'it''s';\n))
    assert_equal ['200', 'a;b{c}'], r.children[0].args
    assert_equal 2, r.children.size
  end

  def test_escaped_quote
    r = NginxAudit.parse(%(set $x "a\\"b";))
    assert_equal ['$x', 'a"b'], r.children[0].args
  end

  def test_multiline_quoted_string_counts_lines
    r = NginxAudit.parse(%(a "x\ny";\nb;))
    assert_equal 3, r.children[1].line
  end

  def test_block_args
    r = NginxAudit.parse("location ~* \\.php$ { }\n")
    assert_equal ['~*', '\\.php$'], r.children[0].args
  end

  def test_errors
    [
      ["http {\n", 'missing }'],
      ["}\n", "unexpected '}'"],
      ["a b\n", 'missing ;'],
      ["http {\nlisten 80\n}", "missing ; before }"],
      ["{ }", 'block with no name'],
      [";", 'no name'],
      [%(a "open;), 'unterminated']
    ].each do |text, frag|
      e = assert_raises(NginxAudit::ParseError, text) { NginxAudit.parse(text) }
      assert_includes e.message, frag
    end
  end

  def test_empty_input
    assert_empty NginxAudit.parse('').children
    assert_empty NginxAudit.parse("\n\n# only a comment\n").children
  end

  def test_fuzz_never_raises_anything_but_parse_error
    srand(42)
    base = %(http {\n server {\n listen 443 ssl;\n location /a { alias /x/; }\n add_header A "b;c";\n }\n}\n)
    3000.times do
      t = base.dup
      (1 + rand(5)).times do
        pos = rand(t.size)
        case rand(3)
        when 0 then t[pos] = ['{', '}', ';', '"', "'", '#', "\n", 'a'].sample
        when 1 then t.slice!(pos, 1 + rand(6))
        else t.insert(pos, ['{', '}', ';', '"', "\\"].sample)
        end
        break if t.empty?
      end
      begin
        NginxAudit.audit(t, 'f.conf')
      rescue StandardError => e
        flunk "unexpected #{e.class} for #{t.inspect}"
      end
    end
  end
end

class RuleTest < Minitest::Test
  def rules(text)
    NginxAudit.audit(text, 't.conf').map(&:rule)
  end

  def server(body, listen: 'listen 443 ssl;')
    "http {\n server_tokens off;\n server {\n #{listen}\n add_header Strict-Transport-Security max-age=1;\n add_header X-Content-Type-Options nosniff;\n #{body}\n }\n}\n"
  end

  def test_clean_config_has_no_findings
    assert_empty rules(server(''))
  end

  def test_autoindex
    assert_includes rules(server('autoindex on;')), 'NGX001'
    refute_includes rules(server('autoindex off;')), 'NGX001'
  end

  def test_server_tokens
    assert_includes rules("http { server_tokens on; }"), 'NGX002'
    assert_includes rules("http { }"), 'NGX002'
    refute_includes rules("http { server_tokens off; }"), 'NGX002'
    f = NginxAudit.audit("http { server_tokens on; }", 't').find { |x| x.rule == 'NGX002' }
    assert_equal 'medium', f.sev
    f = NginxAudit.audit("http { }", 't').find { |x| x.rule == 'NGX002' }
    assert_equal 'low', f.sev
  end

  def test_protocols
    assert_includes rules(server('ssl_protocols TLSv1 TLSv1.2;')), 'NGX003'
    assert_includes rules(server('ssl_protocols SSLv3;')), 'NGX003'
    assert_includes rules(server('ssl_protocols TLSv1.1;')), 'NGX003'
    refute_includes rules(server('ssl_protocols TLSv1.2 TLSv1.3;')), 'NGX003'
  end

  def test_ciphers
    assert_includes rules(server('ssl_ciphers HIGH:RC4-SHA;')), 'NGX004'
    assert_includes rules(server('ssl_ciphers DES-CBC3-SHA;')), 'NGX004'
    assert_includes rules(server('ssl_ciphers EXPORT;')), 'NGX004'
    refute_includes rules(server('ssl_ciphers HIGH:!aNULL:!MD5:!RC4;')), 'NGX004'
    refute_includes rules(server('ssl_ciphers ECDHE-RSA-AES128-GCM-SHA256;')), 'NGX004'
  end

  def test_hsts_and_nosniff
    plain = "http { server_tokens off; server { listen 443 ssl; } }"
    r = rules(plain)
    assert_includes r, 'NGX005'
    assert_includes r, 'NGX008'
    refute_includes rules("http { server_tokens off; server { listen 80; } }"), 'NGX005'
    inherited = "http { server_tokens off; add_header Strict-Transport-Security x; add_header X-Content-Type-Options y; server { listen 443 ssl; } }"
    assert_empty rules(inherited)
    assert_includes rules("http { server_tokens off; server { listen 8443; ssl_certificate a; } }"), 'NGX005'
  end

  def test_alias_off_by_slash
    assert_includes rules(server('location /img { alias /data/img/; }')), 'NGX006'
    refute_includes rules(server('location /img/ { alias /data/img/; }')), 'NGX006'
    refute_includes rules(server('location = /img { alias /data/img.png; }')), 'NGX006'
    refute_includes rules(server('location ~ ^/img { alias /data/img/; }')), 'NGX006'
    f = NginxAudit.audit(server("\n location /img { alias /data/img/; }"), 't').find { |x| x.rule == 'NGX006' }
    assert_equal 'high', f.sev
  end

  def test_body_size
    assert_includes rules(server('client_max_body_size 0;')), 'NGX007'
    assert_includes rules(server('client_max_body_size 0m;')), 'NGX007'
    refute_includes rules(server('client_max_body_size 10m;')), 'NGX007'
  end

  def test_stub_status
    assert_includes rules(server('location /s { stub_status; }')), 'NGX009'
    assert_includes rules(server('location /s { stub_status; allow 10.0.0.1; }')), 'NGX009'
    refute_includes rules(server('location /s { stub_status; allow 10.0.0.1; deny all; }')), 'NGX009'
  end

  def test_proxy_ssl_verify
    assert_includes rules(server('location / { proxy_ssl_verify off; }')), 'NGX010'
    refute_includes rules(server('location / { proxy_ssl_verify on; }')), 'NGX010'
  end

  def test_syntax_problem_is_reported_not_raised
    f = NginxAudit.audit("http {", 'x.conf')
    assert_equal 1, f.size
    assert_equal 'NGX000', f[0].rule
    assert_equal 'info', f[0].sev
  end

  def test_where_has_label_and_line
    f = NginxAudit.audit(server("\n\n autoindex on;"), 'site/a.conf').find { |x| x.rule == 'NGX001' }
    assert_match(%r{\Asite/a\.conf:\d+\z}, f.where)
  end

  def test_sort_orders_by_severity_then_file_then_line
    f = NginxAudit.sort([
      NginxAudit::Finding.new('low', 'B', 'a.conf:1', ''),
      NginxAudit::Finding.new('high', 'A', 'b.conf:9', ''),
      NginxAudit::Finding.new('high', 'A', 'b.conf:10', ''),
      NginxAudit::Finding.new('high', 'A', 'a.conf:2', '')
    ])
    assert_equal %w[a.conf:2 b.conf:9 b.conf:10 a.conf:1], f.map(&:where)
  end
end

class CliTest < Minitest::Test
  BIN = File.expand_path('../bin/nginx-audit', __dir__)
  EX = File.expand_path('../examples/configs', __dir__)

  def run_cli(*args)
    out, err, st = Open3.capture3(RbConfig.ruby, BIN, *args)
    [out, err, st.exitstatus]
  end

  def test_default_exit_zero
    _, _, rc = run_cli(EX)
    assert_equal 0, rc
  end

  def test_fail_on_high
    _, _, rc = run_cli(EX, '--fail-on', 'high')
    assert_equal 1, rc
  end

  def test_clean_file_passes_fail_on_medium
    _, _, rc = run_cli(File.join(EX, 'modern.conf'), '--fail-on', 'medium')
    assert_equal 0, rc
  end

  def test_tsv_header
    out, _, = run_cli(EX, '--tsv')
    assert out.lines.first.start_with?('# ')
    assert out.lines.drop(1).all? { |l| l.count("\t") == 3 }
  end

  def test_bad_input
    assert_equal 2, run_cli('/no/such/path')[2]
    assert_equal 2, run_cli[2]
    assert_equal 2, run_cli(EX, '--bogus')[2]
    assert_equal 2, run_cli(EX, '--fail-on', 'nope')[2]
    assert_equal 2, run_cli(EX, EX)[2]
  end
end

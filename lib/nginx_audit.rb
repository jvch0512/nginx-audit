# frozen_string_literal: true

# nginx configuration parser and auditor. Standard library only.
module NginxAudit
  Finding = Struct.new(:sev, :rule, :where, :msg)
  Directive = Struct.new(:name, :args, :line, :children, :parent) do
    def block? = !children.nil?
  end

  class ParseError < StandardError
    attr_reader :line

    def initialize(msg, line)
      super(msg)
      @line = line
    end
  end

  RANK = { 'critical' => 0, 'high' => 1, 'medium' => 2, 'low' => 3, 'info' => 4 }.freeze

  # Returns a root Directive (name "main") whose children are the top level directives.
  def self.parse(text)
    tokens = tokenize(text)
    root = Directive.new('main', [], 1, [], nil)
    stack = [root]
    words = []
    start = nil
    tokens.each do |kind, tok, line|
      if kind == :word
        start = line if words.empty?
        words << tok
        next
      end
      case tok
      when ';'
        raise ParseError.new('directive with no name', line) if words.empty?

        stack.last.children << Directive.new(words.first, words[1..], start, nil, stack.last)
        words = []
      when '{'
        raise ParseError.new('block with no name', line) if words.empty?

        d = Directive.new(words.first, words[1..], start, [], stack.last)
        stack.last.children << d
        stack << d
        words = []
      when '}'
        raise ParseError.new("unexpected '}'", line) if stack.size == 1
        raise ParseError.new('missing ; before }', line) unless words.empty?

        stack.pop
      end
    end
    raise ParseError.new('unexpected end of file, missing }', start || 1) if stack.size > 1
    raise ParseError.new('missing ; at end of file', start || 1) unless words.empty?

    root
  end

  # Tokens are [:punct | :word, text, line]. A quoted ';' or '{' is a word, never punctuation.
  def self.tokenize(text)
    out = []
    i = 0
    line = 1
    n = text.length
    while i < n
      c = text[i]
      if c == "\n"
        line += 1
        i += 1
      elsif c =~ /\s/
        i += 1
      elsif c == '#'
        i += 1 while i < n && text[i] != "\n"
      elsif c == ';' || c == '{' || c == '}'
        out << [:punct, c.dup, line]
        i += 1
      elsif c == '"' || c == "'"
        start_line = line
        buf = +''
        i += 1
        closed = false
        while i < n
          ch = text[i]
          if ch == '\\' && i + 1 < n
            buf << text[i + 1]
            i += 2
            next
          end
          if ch == c
            closed = true
            i += 1
            break
          end
          line += 1 if ch == "\n"
          buf << ch
          i += 1
        end
        raise ParseError.new('unterminated quoted string', start_line) unless closed

        out << [:word, buf, start_line]
      else
        start = i
        i += 1 while i < n && text[i] !~ /[\s;{}]/
        out << [:word, text[start...i], line]
      end
    end
    out
  end

  def self.walk(node, &blk)
    (node.children || []).each do |c|
      blk.call(c)
      walk(c, &blk) if c.block?
    end
  end

  def self.ancestors(d)
    out = []
    while (d = d.parent)
      out << d
    end
    out
  end

  # Finds the nearest directive called name in the block itself or any ancestor, else nil.
  def self.inherited(block, name)
    node = block
    while node
      found = (node.children || []).find { |c| c.name == name }
      return found if found

      node = node.parent
    end
    nil
  end

  def self.header_set?(block, header)
    node = block
    while node
      (node.children || []).each do |c|
        return true if c.name == 'add_header' && c.args.first.to_s.downcase == header.downcase
      end
      node = node.parent
    end
    false
  end

  def self.tls_server?(server)
    server.children.any? { |c| c.name == 'listen' && (c.args.include?('ssl') || c.args.first.to_s =~ /(\A|:)443\z/) } ||
      server.children.any? { |c| c.name == 'ssl_certificate' }
  end

  OLD_PROTOCOLS = %w[SSLv2 SSLv3 TLSv1 TLSv1.1].freeze
  WEAK_CIPHER = /(RC4|(?<![A-Z0-9])DES(?![A-Z0-9])|3DES|MD5|NULL|EXPORT|aNULL|eNULL|LOW)/i.freeze

  def self.audit(text, label)
    out = []
    begin
      root = parse(text)
    rescue ParseError => e
      return [Finding.new('info', 'NGX000', "#{label}:#{e.line}", "syntax problem: #{e.message}")]
    end
    w = ->(d) { "#{label}:#{d.line}" }

    http_blocks = []
    walk(root) { |d| http_blocks << d if d.name == 'http' && d.block? }
    http_blocks.each do |h|
      out << Finding.new('low', 'NGX002', w.(h), 'server_tokens not set in http: nginx reports its version in headers and error pages') unless h.children.any? { |c| c.name == 'server_tokens' }
    end

    walk(root) do |d|
      case d.name
      when 'autoindex'
        out << Finding.new('medium', 'NGX001', w.(d), 'autoindex on: directory listings are exposed') if d.args.first == 'on'
      when 'server_tokens'
        out << Finding.new('medium', 'NGX002', w.(d), 'server_tokens on: version is disclosed') if d.args.first == 'on'
      when 'ssl_protocols'
        bad = d.args & OLD_PROTOCOLS
        out << Finding.new('high', 'NGX003', w.(d), "obsolete protocols enabled: #{bad.join(', ')}") unless bad.empty?
      when 'ssl_ciphers'
        s = d.args.join(':')
        m = s.split(':').reject { |p| p.start_with?('!') || p.start_with?('-') }.select { |p| p =~ WEAK_CIPHER }
        out << Finding.new('high', 'NGX004', w.(d), "weak ciphers allowed: #{m.first(4).join(', ')}") unless m.empty?
      when 'location'
        alias_d = d.children&.find { |c| c.name == 'alias' }
        if alias_d
          prefix = d.args.last.to_s
          target = alias_d.args.first.to_s
          plain = d.args.none? { |a| a == '=' || a.start_with?('~') }
          if plain && prefix.start_with?('/') && !prefix.end_with?('/') && target.end_with?('/')
            out << Finding.new('high', 'NGX006', w.(alias_d), "location #{prefix} has no trailing slash but alias #{target} does: a request for #{prefix}../ can leave the directory")
          end
        end
        if d.children&.any? { |c| c.name == 'stub_status' }
          protected = d.children.any? { |c| c.name == 'allow' } && d.children.any? { |c| c.name == 'deny' }
          out << Finding.new('medium', 'NGX009', w.(d), 'stub_status is exposed without allow and deny rules') unless protected
        end
      when 'client_max_body_size'
        out << Finding.new('low', 'NGX007', w.(d), 'client_max_body_size 0 disables the upload limit') if d.args.first.to_s =~ /\A0[kKmMgG]?\z/
      when 'proxy_ssl_verify'
        out << Finding.new('medium', 'NGX010', w.(d), 'proxy_ssl_verify off: upstream certificates are not checked') if d.args.first == 'off'
      when 'server'
        next unless d.block? && tls_server?(d)

        unless header_set?(d, 'Strict-Transport-Security')
          at = d.children.find { |c| c.name == 'listen' } || d
          out << Finding.new('medium', 'NGX005', w.(at), 'TLS server without a Strict-Transport-Security header')
        end
        unless header_set?(d, 'X-Content-Type-Options')
          at = d.children.find { |c| c.name == 'listen' } || d
          out << Finding.new('low', 'NGX008', w.(at), 'TLS server without an X-Content-Type-Options header')
        end
      end
    end
    out
  end

  def self.sort(findings)
    findings.sort_by { |f| [RANK[f.sev], f.where.sub(/:\d+\z/, ''), f.where[/:(\d+)\z/, 1].to_i, f.rule] }
  end
end

module Rack
  class SslEnforcer
    
    def initialize(app, options = {})
      @app, @options = app, options
    end
    
    def call(env)
      @req = Rack::Request.new(env)
      if enforce_ssl?(@req)
        scheme = 'https' unless ssl_request?(env)
      elsif ssl_request?(env) && @options[:strict]
        scheme = 'http'
      end

      if scheme
        location = @options[:redirect_to] || replace_scheme(@req, scheme).url
        body     = "<html><body>You are being <a href=\"#{location}\">redirected</a>.</body></html>"
        [301, { 'Content-Type' => 'text/html', 'Location' => location }, [body]]
      elsif ssl_request?(env)
        status, headers, body = @app.call(env)
        flag_cookies_as_secure!(headers)
        set_hsts_headers!(headers) if @options[:hsts]
        [status, headers, body]
      else
        @app.call(env)
      end
    end
    
    
  private
    
    def ssl_request?(env)
      scheme(env) == 'https'
    end
    
    # Fixed in rack >= 1.3
    def scheme(env)
      if env['HTTPS'] == 'on'
        'https'
      elsif env['HTTP_X_FORWARDED_PROTO']
        env['HTTP_X_FORWARDED_PROTO'].split(',')[0]
      else
        env['rack.url_scheme']
      end
    end

    def enforce_ssl?(req)
      if enforced_host?(req)
        enforced_path?(req)
      else
        false
      end
    end

    def enforced_host? req
      enforced = true
      enforced &&= matches_only?(req.host, @options[:only_hosts])
      enforced &&= !matches_except?(req.host, @options[:except_hosts])
    end

    def enforced_path? req
      enforced = true
      enforced &&= matches_only?(req.path, @options[:only])
      enforced &&= !matches_except?(req.path, @options[:except])
    end

    def matches_only? pattern, rules
      return true unless rules
      [rules].flatten.compact.any?{|r| r.is_a?(Regexp) ? r =~ pattern : r == pattern[0,r.length]}
    end

    def matches_except? pattern, rules
      return false unless rules
      [rules].flatten.compact.any?{|r| r.is_a?(Regexp) ? r =~ pattern : r == pattern[0,r.length]}
    end

    def replace_scheme(req, scheme)
      Rack::Request.new(req.env.merge(
        'rack.url_scheme' => scheme,
        'HTTP_X_FORWARDED_PROTO' => scheme,
        'HTTP_X_FORWARDED_PORT' => port_for(scheme).to_s,
        'SERVER_PORT' => port_for(scheme).to_s
      ))
    end
    
    def port_for(scheme)
      scheme == 'https' ? 443 : 80
    end

    # see http://en.wikipedia.org/wiki/HTTP_cookie#Cookie_hijacking
    def flag_cookies_as_secure!(headers)
      if cookies = headers['Set-Cookie']
        headers['Set-Cookie'] = cookies.split("\n").map { |cookie|
          if cookie !~ / secure;/
            "#{cookie}; secure"
          else
            cookie
          end
        }.join("\n")
      end
    end
    
    # see http://en.wikipedia.org/wiki/Strict_Transport_Security
    def set_hsts_headers!(headers)
      opts = { :expires => 31536000, :subdomains => true }.merge(@options[:hsts] || {})
      value  = "max-age=#{opts[:expires]}"
      value += "; includeSubDomains" if opts[:subdomains]
      headers.merge!({ 'Strict-Transport-Security' => value })
    end
    
  end
end

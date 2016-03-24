#--
# Cloud Foundry
# Copyright (c) [2009-2014] Pivotal Software, Inc. All Rights Reserved.
#
# This product is licensed to you under the Apache License, Version 2.0 (the "License").
# You may not use this product except in compliance with the License.
#
# This product includes a number of subcomponents with
# separate copyright notices and license terms. Your use of these
# subcomponents is subject to the terms and conditions of the
# subcomponent's license, as noted in the LICENSE file.
#++

require 'cli/common'
require 'launchy'
require 'uaa'
require 'stub/server'

module CF::UAA

class TokenCatcher < Stub::Base

  def process_grant(data)
    server.logger.debug "processing grant for path #{request.path}"
    secret = server.info.delete(:client_secret)
    ti = TokenIssuer.new(Config.target, server.info.delete(:client_id), secret,
        { token_target: Config.target_value(:token_target),
          skip_ssl_validation: Config.target_value(:skip_ssl_validation)})
    tkn = secret ? ti.authcode_grant(server.info.delete(:uri), data) :
        ti.implicit_grant(server.info.delete(:uri), data)
    server.info.update(token_info: tkn.info)
    reply.text "you are now logged in and can close this window"
  rescue TargetError => e
    reply.text "#{e.message}:\r\n#{Util.json_pretty(e.info)}\r\n#{e.backtrace}"
  rescue Exception => e
    reply.text "#{e.message}\r\n#{e.backtrace}"
  ensure
    server.logger.debug "reply: #{reply.body}"
  end

  route :get, '/favicon.ico' do
    reply.headers['content-type'] = "image/vnd.microsoft.icon"
    reply.body = File.read File.expand_path(File.join(__FILE__, '..', 'favicon.ico'))
  end

  route :get, %r{^/authcode\?(.*)$} do process_grant match[1] end
  route :post, '/callback' do process_grant request.body end
  route :get, '/callback' do
    server.logger.debug "caught redirect back from UAA after authentication"
    reply.headers['content-type'] = "text/html"
    reply.body = <<-HTML.gsub(/^ +/, '')
      <html><body><script type="text/javascript">
      var fragment = location.hash.substring(1);
      var req = new XMLHttpRequest();
      //document.write(fragment + "<br><br>");
      req.open('POST', "/callback", false);
      req.setRequestHeader("Content-type","application/x-www-form-urlencoded");
      req.send(fragment);
      document.write(req.responseText);
      </script></body></html>
    HTML
  end
end

class TokenCli < CommonCli

  topic "Tokens", "token", "login"

  def say_success(grant)
    say "\nSuccessfully fetched token via #{grant} grant.\nTarget: #{Config.target}\nContext: #{Config.context}, from client #{Config[:client_id]}\n\n"
  end

  def set_context(token_info)
    return gripe "attempt to get token failed\n" unless token_info && token_info["access_token"]
    contents = TokenCoder.decode(token_info["access_token"], verify: false)
    Config.context = contents["user_name"] || contents["client_id"] || "bad_token"
    did_save = true
    (did_save &= Config.add_opts(user_id: contents["user_id"])) if contents["user_id"]
    (did_save &= Config.add_opts(client_id: contents["client_id"])) if contents["client_id"]
    jti = token_info.delete("jti") if token_info.has_key? "jti"
    did_save &= Config.add_opts token_info
    (did_save &= Config.add_opts(scope: contents["scope"])) if contents["scope"]
    (did_save &= Config.add_opts(jti: jti)) if jti
    did_save
  end

  def issuer_request(client_id, secret = nil)
    update_target_info
    yield TokenIssuer.new(Config.target.to_s, client_id, secret,
        { token_target: Config.target_value(:token_endpoint),
          skip_ssl_validation: Config.target_value(:skip_ssl_validation),
          ssl_ca_file: Config.target_value(:ca_cert) })
  rescue Exception => e
    complain e
  end

  define_option :client, "--client <name>", "-c"
  define_option :scope, "--scope <list>"
  desc "token get [credentials...]",
      "Gets a token by posting user credentials with an implicit grant request",
      :client, :scope do |*args|
    client_name = opts[:client] || "cf"
    reply = issuer_request(client_name, "") { |ti|
      prompts = ti.prompts
      creds = {}
      prompts.each do |k, v|
        if arg = args.shift
          creds[k] = arg
        elsif v[0] == "text"
          creds[k] = ask(v[1])
        elsif v[0] == "password"
          creds[k] = ask_pwd v[1]
        else
          raise "Unknown prompt type \"#{v[0]}\" received from #{Context.target}"
        end
      end
      ti.implicit_grant_with_creds(creds, opts[:scope]).info
    }
    say_success "implicit (with posted credentials)" if set_context(reply)
  end

  define_option :secret, "--secret <secret>", "-s", "client secret"
  desc "token client get [id]",
      "Gets a token with client credentials grant", :secret, :scope do |id|
    reply = issuer_request(clientid(id), clientsecret) { |ti|
      ti.client_credentials_grant(opts[:scope]).info
    }
    say_success "client credentials" if set_context(reply)
  end

  define_option :password, "-p", "--password <password>", "user password"
  desc "token owner get [client] [user]", "Gets a token with a resource owner password grant",
      :secret, :password, :scope do |client, user|
    reply = issuer_request(clientid(client), clientsecret) { |ti|
        ti.owner_password_grant(user = username(user), userpwd, opts[:scope]).info
    }
    say_success "owner password" if set_context(reply)
  end

  define_option :passcode, "--passcode <passcode>"
  desc "token sso get [client]", "Gets a token based on a one time passcode after successful SSO via browser",
       :secret,:passcode,:scope do |client|
    reply = issuer_request(clientid(client), clientsecret) { |ti|
      ti.passcode_grant(passcode, opts[:scope]).info
    }
    say_success "owner passcode" if set_context(reply)
  end

  desc "token refresh [refreshtoken]", "Gets a new access token from a refresh token", :client, :secret, :scope do |rtok|
    rtok ||= Config.value(:refresh_token)
    reply = issuer_request(clientid, clientsecret) { |ti| ti.refresh_token_grant(rtok, opts[:scope]).info }
    say_success "refresh" if set_context(reply)
  end

  CF_TOKEN_FILE = File.join ENV["HOME"], ".cf_token"
  CF_TARGET_FILE = File.join ENV["HOME"], ".cf_target"

  def use_browser(client_id, secret = nil)
    catcher = Stub::Server.new(TokenCatcher,
        logger: Util.default_logger(debug? ? :debug : trace? ? :trace : :info),
        info: {client_id: client_id, client_secret: secret},
        port: opts[:port]).run_on_thread
    uri = issuer_request(client_id, secret) { |ti|
      secret ? ti.authcode_uri("#{catcher.url}/authcode", opts[:scope]) :
          ti.implicit_uri("#{catcher.url}/callback", opts[:scope])
    }
    return unless catcher.info[:uri] = uri
    say "launching browser with #{uri}" if trace?
    Launchy.open(uri, debug: true, dry_run: false)
    print "waiting for token "
    while catcher.info[:uri] || !catcher.info[:token_info]
      sleep 5
      print "."
    end
    say_success(secret ? "authorization code" : "implicit") if set_context(catcher.info[:token_info])
    return unless opts[:cf]
    begin
      cf_target = File.open(CF_TARGET_FILE, 'r') { |f| f.read.strip }
      tok_json = File.open(CF_TOKEN_FILE, 'r') { |f| f.read } if File.exists?(CF_TOKEN_FILE)
      cf_tokens = Util.json_parse(tok_json, :none) || {}
      cf_tokens[cf_target] = auth_header
      File.open(CF_TOKEN_FILE, 'w') { |f| f.write(cf_tokens.to_json) }
    rescue Exception => e
      gripe "\nUnable to save token to cf token file"
      complain e
    end
  end

  define_option :port, "--port <number>", "pin internal server to specific port"
  define_option :cf, "--[no-]cf", "save token in the ~/.cf_tokens file"
  desc "token authcode get", "Gets a token using the authcode flow with browser",
      :client, :secret, :scope, :cf, :port do use_browser(clientid, clientsecret) end

  desc "token implicit get", "Gets a token using the implicit flow with browser",
      :client, :scope, :cf, :port do use_browser opts[:client] || "cf" end

  define_option :key, "--key <key>", "Token validation key"
  desc "token decode [token] [tokentype]", "Show token contents as parsed locally or by the UAA. " +
   "Decodes locally unless --client and --secret are given. Validates locally if --key given or server's signing key has been retrieved",
      :key, :client, :secret do |token, ttype|
    ttype = "bearer" if token && !ttype
    token ||= Config.value(:access_token)
    ttype ||= Config.value(:token_type)
    return say "no token to decode" unless token && ttype
    handle_request do
      if opts[:client] && opts[:secret]
        pp @cli_class.uaa_info_client.decode_token(opts[:client], opts[:secret], token, ttype)
      else
        seckey = opts[:key] || (Config.target_value(:signing_key) if Config.target_value(:signing_alg) !~ /rsa$/i)
        pubkey = opts[:key] || (Config.target_value(:signing_key) if Config.target_value(:signing_alg) =~ /rsa$/i)
        info = TokenCoder.decode(token, skey: seckey, pkey: pubkey, verify: !!(seckey || pubkey))
        say seckey || pubkey ? "\nValid token signature\n\n": "\nNote: no key given to validate token signature\n\n"
        pp info
      end
    end
  end

  define_option :all, "--[no-]all", "remove all contexts"
  desc "token delete [contexts...]",
      "Delete current or specified context tokens and settings", :all do |*args|
    begin
      return Config.delete if opts[:all]
      return args.each { |arg| Config.delete(Config.target, arg.to_i.to_s == arg ? arg.to_i : arg) } unless args.empty?
      return Config.delete(Config.target, Config.context) if Config.context
      say "no target set, no contexts given -- nothing to delete"
    rescue Exception => e
      complain e
    end
  end

end

end

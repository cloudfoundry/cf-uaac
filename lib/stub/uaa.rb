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

require 'uaa'
require 'stub/server'
require 'stub/scim'
require 'cli/version'
require 'pp'

module CF::UAA

class StubUAAConn < Stub::Base

  def inject_error(input = nil)
    case server.reply_badly
    when :non_json then reply.text("non-json reply")
    when :bad_json then reply.body = %<{"access_token":"good.access.token" "missed a comma":"there"}>
    when :bad_state then input[:state] = "badstate"
    when :no_token_type then input.delete(:token_type)
    end
  end

  def bad_request(msg = nil); reply_in_kind(400, error: "bad request#{msg ? ',' : ''} #{msg}") end
  def not_found(name = nil); reply_in_kind(404, error: "#{name} not found") end
  def access_denied(msg = "access denied") reply_in_kind(403, error: "access_denied", error_description: msg) end
  def ids_to_names(ids); ids ? ids.map { |id| server.scim.name(id) } : [] end
  def names_to_ids(names, rtype); names ? names.map { |name| server.scim.id(name, rtype) } : [] end
  def encode_cookie(obj = {}) Util.json_encode64(obj) end
  def decode_cookie(str) Util.json.decode64(str) end

  def valid_token(accepted_scope)
    return nil unless (ah = request.headers["authorization"]) && (ah = ah.split(' '))[0] =~ /^bearer$/i
    contents = TokenCoder.decode(ah[1], accept_algorithms: "none")
    contents["scope"], accepted_scope = Util.arglist(contents["scope"]), Util.arglist(accepted_scope)
    return contents if accepted_scope.nil? || !(accepted_scope & contents["scope"]).empty?
    access_denied("accepted scope #{Util.strlist(accepted_scope)}")
  end

  def primary_email(emails)
    return unless emails
    emails.each {|e| return e[:value] if e[:type] && e[:type] == "primary"}
    emails[0][:value]
  end

  def find_user(name, pwd = nil)
    user = server.scim.get_by_name(name, :user, :password, :id, :emails, :username, :groups)
    user if user && (!pwd || user[:password] == pwd)
  end

  #----------------------------------------------------------------------------
  # miscellaneous endpoints
  #

  def default_route; reply_in_kind(404, error: "not found", error_description: "unknown path #{request.path}") end

  route :get, '/favicon.ico' do
    reply.headers[:content_type] = "image/vnd.microsoft.icon"
    reply.body = File.read File.expand_path(File.join(__FILE__, '..', '..', 'lib', 'cli', 'favicon.ico'))
  end

  route :put, '/another-fake-endpoint' do
    return unless valid_token("clients.read")
    parsed = JSON.parse(request.body)
    reply_in_kind(202, parsed.merge(:updated => 42))
  end

  route :put, '/fake-endpoint-empty-response' do
    return unless valid_token("clients.read")
    reply.empty()
  end

  route :get, '/my-fake-endpoint' do
    return unless valid_token("clients.read")
    reply_in_kind(200, "some fake response text")
  end

  route :get, '/' do reply_in_kind "welcome to stub UAA, version #{VERSION}" end
  route :get, '/varz' do reply_in_kind(mem: 0, type: 'UAA', app: { version: VERSION } ) end
  route :get, '/token_key' do reply_in_kind(alg: "none", value: "none") end

  route :post, '/password/score', "content-type" => %r{application/x-www-form-urlencoded} do
    info = Util.decode_form(request.body)
    return bad_request "no password to score" unless pwd = info["password"]
    score = pwd.length > 10 || pwd.length < 0 ? 10 : pwd.length
    reply_in_kind(score: score, requiredScore: 0)
  end

  route :get, %r{^/userinfo(\?|$)(.*)} do
    return not_found unless (tokn = valid_token("openid")) &&
        (info = server.scim.get(tokn["user_id"], :user, :username, :id, :emails)) && info[:username]
    reply_in_kind(user_id: info[:id], user_name: info[:username], email: primary_email(info[:emails]))
  end

  route :get, '/login' do
    return reply_in_kind(server.info) unless request.headers["accept"] =~ /text\/html/
    session = decode_cookie(request.cookies["stubsession"]) || {}
    if session["username"]
      page = <<-DATA.gsub(/^ +/, '')
        you are logged in as #{session["username"]}
        <form id='logout' action='login.do' method='get' accept-charset='UTF-8'>
        <input type='submit' name='submit' value='Logout' /></form>
      DATA
    else
      page = <<-DATA.gsub(/^ +/, '')
        <form id='login' action='login.do' method='post' accept-charset='UTF-8'>
        <fieldset><legend>Login</legend><label for='username'>User name:</label>
        <input type='text' name='username' id='username' maxlength='50' />
        <label for='password'>Password:</label>
        <input type='password' name='password' id='password' maxlength='50' />
        <input type='submit' name='submit' value='Login' /></fieldset></form>
      DATA
    end
    reply.html page
    #reply.set_cookie(:stubsession, encode_cookie(session), httponly: nil)
  end

  route :post, '/login.do', "content-type" => %r{application/x-www-form-urlencoded} do
    creds = Util.decode_form(request.body)
    user = find_user(creds['username'], creds['password'])
    reply.headers[:location] = "login"
    reply.status = 302
    reply.set_cookie(:stubsession, encode_cookie(username: user[:username], httponly: nil))
  end

  route :get, %r{^/logout.do(\?|$)(.*)} do
    query = Util.decode_form(match[2])
    reply.headers[:location] = query['redirect_uri'] || "login"
    reply.status = 302
    reply.set_cookie(:stubsession, encode_cookie, max_age: -1)
  end


  #----------------------------------------------------------------------------
  # oauth2 endpoints and helpers
  #

  # current uaa token contents: exp, user_name, scope, email, user_id,
  #    client_id, client_authorities, user_authorities
  def token_reply_info(client, scope, user = nil, state = nil, refresh = false)
    interval = client[:access_token_validity] || 3600
    token_body = { jti: SecureRandom.uuid, aud: scope, scope: scope,
        client_id: client[:client_id], exp: interval + Time.now.to_i }
    if user
      token_body[:user_id] = user[:id]
      token_body[:email] = primary_email(user[:emails])
      token_body[:user_name] = user[:username]
    end
    info = { access_token: TokenCoder.encode(token_body, :algorithm => 'none'),
        token_type: "bearer", expires_in: interval, scope: scope}
    info[:state] = state if state
    info[:refresh_token] = "universal_refresh_token" if refresh
    inject_error(info)
    info
  end

  def auth_client(basic_auth_header)
    ah = basic_auth_header.split(' ')
    return unless ah[0] =~ /^basic$/i
    ah = Base64::strict_decode64(ah[1]).split(':')
    client = server.scim.get_by_name(ah[0], :client)
    client if client && client[:client_secret] == ah[1]
  end

  def valid_redir_uri?(client, redir_uri)
    t = URI.parse(redir_uri)
    return true unless (ruris = client[:redirect_uris]) && !ruris.empty?
    false unless ruris.each { |reg_uri|
      r = URI.parse(reg_uri)
      return true if r.scheme == t.scheme && r.host == t.host &&
          (!r.port || r.port == t.port) && (!r.path || r.path == t.path)
    }
  end

  def redir_with_fragment(cburi, params)
    reply.status = 302
    uri = URI.parse(cburi)
    uri.fragment = Util.encode_form(params)
    reply.headers[:location] = uri.to_s
  end

  def redir_with_query(cburi, params)
    reply.status = 302
    uri = URI.parse(cburi)
    uri.query = Util.encode_form(params)
    reply.headers[:location] = uri.to_s
  end

  def redir_err_f(cburi, state, msg); redir_with_fragment(cburi, error: msg, state: state) end
  def redir_err_q(cburi, state, msg); redir_with_query(cburi, error: msg, state: state) end

  # returns granted scopes
  # TODO: doesn't handle actual user authorization yet
  def calc_scope(client, user, requested_scope)
    possible_scope = ids_to_names(client[user ? :scope : :authorities])
    requested_scope = Util.arglist(requested_scope) || []
    return unless (requested_scope - possible_scope).empty?
    requested_scope = possible_scope if requested_scope.empty?
    granted_scopes = user ? (ids_to_names(user[:groups]) & requested_scope) : requested_scope # handle auto-deny
    Util.strlist(granted_scopes) unless granted_scopes.empty?
  end

  route [:post, :get], %r{^/oauth/authorize\?(.*)} do
    query = Util.decode_form(match[1])
    client = server.scim.get_by_name(query["client_id"], :client)
    cburi, state = query["redirect_uri"], query["state"]

    # if invalid client_id or redir_uri: inform resource owner, do not redirect
    unless client && valid_redir_uri?(client, cburi)
      return bad_request "invalid client_id or redirect_uri"
    end
    if query["response_type"] == 'token'
      unless client[:authorized_grant_types].include?("implicit")
        return redir_err_f(cburi, state, "unauthorized_client")
      end
      if request.method == "post"
        unless request.headers["content-type"] =~ %r{application/x-www-form-urlencoded} &&
            (creds = Util.decode_form(request.body)) &&
            creds["source"] && creds["source"] == "credentials"
          return redir_err_f(cburi, state, "invalid_request")
        end
        unless user = find_user(creds["username"], creds["password"])
          return redir_err_f(cburi, state, "access_denied")
        end
      else
        return reply.status = 501 # TODO: how to authN user and ask for authorizations?
      end
      unless (granted_scope = calc_scope(client, user, query["scope"]))
        return redir_err_f(cburi, state, "invalid_scope")
      end
      # TODO: how to stub any remaining scopes that are not auto-approve?
      token_reply_info = token_reply_info(client, granted_scope, user, query["state"])
      token_reply_info.delete(:scope) if query["scope"]
      return redir_with_fragment(cburi, token_reply_info)
    end
    return redir_err_q(cburi, state, "invalid_request") unless request.method == "get"
    return redir_err_q(cburi, state, "unsupported_response_type") unless query["response_type"] == 'code'
    unless client[:authorized_grant_types].include?("authorization_code")
      return redir_err_f(cburi, state, "unauthorized_client")
    end
    return reply.status = 501 unless query["emphatic_user"] # TODO: how to authN user and ask for authorizations?
    return redir_err_f(cburi, state, "access_denied") unless user = find_user(query["emphatic_user"])
    scope = calc_scope(client, user, query["scope"])
    redir_with_query(cburi, state: state, code: assign_auth_code(client[:id], user[:id], scope, cburi))
  end

  # if required and optional arrays are given, extra params are an error
  def bad_params?(params, required, optional = nil)
    required.each {|r|
      next if params[r]
      reply.json(400, error: "invalid_request", error_description: "no #{r} in request")
      return true
    }
    return false unless optional
    params.each {|k, v|
      next if required.include?(k) || optional.include?(k)
      reply.json(400, error: "invalid_request", error_description: "#{k} not allowed")
      return true
    }
    false
  end

  # TODO: need to save scope, timeout, client, redir_url, user_id, etc
  # when redeeming an authcode, code and redir_url must match
  @authcode_store = {}
  class << self; attr_accessor :authcode_store end
  def assign_auth_code(client_id, user_id, scope, redir_uri)
    code = SecureRandom.base64(8)
    raise "authcode collision" if self.class.authcode_store[code]
    self.class.authcode_store[code] = {client_id: client_id, user_id: user_id,
        scope: scope, redir_uri: redir_uri}
    code
  end
  def redeem_auth_code(client_id, redir_uri, code)
    return unless info = self.class.authcode_store.delete(code)
    return unless info[:client_id] == client_id && info[:redir_uri] == redir_uri
    [info[:user_id], info[:scope]]
  end

  route :post, "/oauth/token", "content-type" => %r{application/x-www-form-urlencoded},
        "accept" => %r{application/json} do
    unless client = auth_client(request.headers["authorization"])
      reply.headers[:www_authenticate] = "basic"
      return reply.json(401, error: "invalid_client")
    end
    return if bad_params?(params = Util.decode_form(request.body), ['grant_type'])
    unless client[:authorized_grant_types].include?(params['grant_type'])
      return reply.json(400, error: "unauthorized_client")
    end
    case params.delete('grant_type')
    when "authorization_code"
       # TODO: need authcode store with requested scope, redir_uri must match
      return if bad_params?(params, ['code', 'redirect_uri'], [])
      user_id, scope = redeem_auth_code(client[:id], params['redirect_uri'], params['code'])
      return reply.json(400, error: "invalid_grant") unless user_id && scope
      user = server.scim.get(user, :user, :id, :emails, :username)
      reply.json(token_reply_info(client, scope, user, nil, true))
    when "password"
      notPassword = bad_params?(params, ['username', 'password'], ['scope'])
      notPasscode = bad_params?(params, ['passcode'], ['scope'])
      return if notPasscode && notPassword
      unless notPassword
        username = params['username']
        password = params['password']
      end
      unless notPasscode
        username, password = Base64::urlsafe_decode64(params['passcode']).split
      end
      user = find_user(username, password)
      return reply.json(400, error: "invalid_grant") unless user
      scope = calc_scope(client, user, params['scope'])
      return reply.json(400, error: "invalid_scope") unless scope
      reply.json(200, token_reply_info(client, scope, user))
    when "client_credentials"
      return if bad_params?(params, [], ['scope'])
      scope = calc_scope(client, nil, params['scope'])
      return reply.json(400, error: "invalid_scope") unless scope
      reply.json(token_reply_info(client, scope))
    when "refresh_token"
      return if bad_params?(params, ['refresh_token'], ['scope'])
      return reply.json(400, error: "invalid_grant") unless params['refresh_token'] == "universal_refresh_token"
      # TODO: max scope should come from refresh token, or user from refresh token
      # this should use calc_scope when we know the user
      scope = ids_to_names(client[:scope])
      scope = Util.strlist(Util.arglist(params['scope'], scope) & scope)
      return reply.json(400, error: "invalid_scope") if scope.empty?
      reply.json(token_reply_info(client, scope))
    else
      reply.json(400, error: "unsupported_grant_type")
    end
    inject_error
  end

  route :post, "/alternate/oauth/token", "content-type" => %r{application/x-www-form-urlencoded},
        "accept" => %r{application/json} do
    request.path.replace("/oauth/token")
    server.info.delete(:token_endpoint) # this indicates this was executed for a unit test
    process
  end

  #----------------------------------------------------------------------------
  # client endpoints
  #
  def client_to_scim(info)
    ['authorities', 'scope', 'autoapprove'].each { |a| info[a] = names_to_ids(info[a], :group) if info.key?(a) }
    info
  end

  def scim_to_client(info)
    [:authorities, :scope, :autoapprove].each { |a| info[a] = ids_to_names(info[a]) if info.key?(a) }
    info.delete(:id)
    info
  end

  route :get, %r{^/oauth/clients(\?|$)(.*)} do
    return unless valid_token("clients.read")
    info, _ = server.scim.find(:client)
    reply_in_kind(info.each_with_object({}) {|c, o| o[c[:client_id]] = scim_to_client(c)})
  end

  route :post, '/oauth/clients', "content-type" => %r{application/json} do
    return unless valid_token("clients.write")
    id = server.scim.add(:client, client_to_scim(Util.json_parse(request.body, :down)))
    reply_in_kind scim_to_client(server.scim.get(id, :client, *StubScim::VISIBLE_ATTRS[:client]))
  end

  route :put, %r{^/oauth/clients/([^/]+)$}, "content-type" => %r{application/json} do
    return unless valid_token("clients.write")
    info = client_to_scim(Util.json_parse(request.body, :down))
    server.scim.update(server.scim.id(match[1], :client), info)
    reply.json(scim_to_client(info))
  end

  route :get, %r{^/oauth/clients/([^/]+)$} do
    return unless valid_token("clients.read")
    return not_found(match[1]) unless client = server.scim.get_by_name(match[1], :client, *StubScim::VISIBLE_ATTRS[:client])
    reply_in_kind(scim_to_client(client))
  end

  route :delete, %r{^/oauth/clients/([^/]+)$} do
    return unless valid_token("clients.write")
    return not_found(match[1]) unless server.scim.delete(server.scim.id(match[1], :client))
  end

  route :put, %r{^/oauth/clients/([^/]+)/secret$}, "content-type" => %r{application/json} do
    info = Util.json_parse(request.body, :down)
    return not_found(match[1]) unless id = server.scim.id(match[1], :client)
    return bad_request("no new secret given") unless info['secret']
    if oldsecret = info['oldsecret']
      return unless valid_token("clients.secret")
      return not_found(match[1]) unless client = server.scim.get(id, :client, :client_secret)
      return bad_request("old secret does not match") unless oldsecret == client[:client_secret]
    else
      return unless valid_token("uaa.admin")
    end
    server.scim.set_hidden_attr(id, :client_secret, info['secret'])
    reply.json(status: "ok", message: "secret updated")
  end

  #----------------------------------------------------------------------------
  # users and groups endpoints
  #
  route :post, %r{^/(Users|Groups)$}, "content-type" => %r{application/json} do
    return unless valid_token("scim.write")
    rtype = match[1] == "Users"? :user : :group
    id = server.scim.add(rtype, Util.json_parse(request.body, :down))
    server.auto_groups.each {|g| server.scim.add_member(g, id)} if rtype == :user && server.auto_groups
    reply_in_kind server.scim.get(id, rtype, *StubScim::VISIBLE_ATTRS[rtype])
  end

  def obj_access?(rtype, oid, perm)
    major_scope = perm == :writers ? "scim.write" : "scim.read"
    return unless tkn = valid_token("#{major_scope} scim.me")
    return tkn if tkn["scope"].include?(major_scope) ||
        rtype == :group && server.scim.is_member(oid, tkn["user_id"], perm)
    access_denied
  end

  route :put, %r{^/(Users|Groups)/([^/]+)$}, "content-type" => %r{application/json} do
    rtype = match[1] == "Users"? :user : :group
    return unless obj_access?(rtype, match[2], :writers)
    version = request.headers['if-match']
    version = version.to_i if version.to_i.to_s == version
    begin
      id = server.scim.update(match[2], Util.json_parse(request.body, :down), version, rtype)
      reply_in_kind server.scim.get(id, rtype, *StubScim::VISIBLE_ATTRS[rtype])
    rescue BadVersion; reply_in_kind(409, error: "invalid object version")
    rescue NotFound; not_found(match[2])
    end
  end

  route :post, %r{^/Groups/External$}, "content-type" => %r{application/json} do
    json = Util.json_parse(request.body, :down)
    external_group = json["externalgroup"]
    group_name = json["displayname"]
    group_id = json["groupid"]
    origin = json["origin"]
    group = server.scim.add_group_mapping(external_group, group_id, group_name, origin)
    reply_in_kind(displayName: group[:displayname], externalGroup: external_group, groupId: group[:id], origin: origin)
  end

  route :get, %r{^/Groups/External/list(\?|$)(.*)} do
    return unless valid_token("scim.read")

    query_params = CGI::parse(match[2])

    start_index_param = query_params["startIndex"].first
    start_index = start_index_param.empty? ? 1 : start_index_param.to_i

    count_param = query_params["count"].first
    count = count_param.empty? ? 100 : count_param.to_i

    group_mappings = server.scim.get_group_mappings
    paginated_group_mappings = group_mappings.slice([start_index,1].max - 1, count)

    reply_in_kind(resources: paginated_group_mappings, itemsPerPage: count, startIndex: start_index, totalResults: group_mappings.length)
  end

  route :delete, %r{^/Groups/External/groupId/([^/]+)/externalGroup/([^/]+)/origin/([^/]+)$} do
    return unless valid_token("scim.write")

    group_id = match[1]
    external_group = match[2]
    origin = match[3]
    begin
      server.scim.delete_group_mapping(group_id, external_group, origin)
    rescue NotFound
      not_found("Mapping for group ID #{match[1]} and external group #{match[2]}")
    end
  end

  def sanitize_int(arg, default, min, max = nil)
    return default if arg.nil?
    return unless arg.to_i.to_s == arg && (i = arg.to_i) >= min
    max && i > max ? max : i
  end

  def page_query(rtype, query, attrs, acl = nil, acl_id = nil)
    if query['attributes']
      attrs = attrs & Util.arglist(query['attributes']).each_with_object([]) {|a, o|
        o << a.to_sym if StubScim::ATTR_NAMES.include?(a = a.downcase)
      }
    end
    start = sanitize_int(query['startindex'], 1, 1)
    count = sanitize_int(query['count'], 15, 1, 3000)
    return bad_request("invalid startIndex or count") unless start && count
    info, total = server.scim.find(rtype, start: start - 1, count: count,
        filter: query['filter'], attrs: attrs, acl: acl, acl_id: acl_id)
    reply_in_kind(resources: info, itemsPerPage: info.length, startIndex: start, totalResults: total)
  end

  route :get, %r{^/(Users|Groups)(\?|$)(.*)} do
    rtype = match[1] == "Users"? :user : :group
    return unless tkn = valid_token("scim.read scim.me")
    acl = acl_id = nil
    unless tkn["scope"].include?("scim.read")
      acl, acl_id = :readers, tkn["user_id"]
      return access_denied unless rtype == :group && acl_id
    end
    page_query(rtype, Util.decode_form(match[3], :down),
        StubScim::VISIBLE_ATTRS[rtype], acl, acl_id)
  end

  route :get, %r{^/(Users|Groups)/([^/]+)$} do
    rtype = match[1] == "Users"? :user : :group
    return unless obj_access?(rtype, match[2], :readers)
    return not_found(match[2]) unless obj = server.scim.get(match[2], rtype, *StubScim::VISIBLE_ATTRS[rtype])
    reply_in_kind(obj)
  end

  route :delete, %r{^/(Users|Groups)/([^/]+)$} do
    return unless valid_token("scim.write")
    not_found(match[2]) unless server.scim.delete(match[2], match[1] == "Users"? :user : :group)
  end

  route :put, %r{^/Users/([^/]+)/password$}, "content-type" => %r{application/json} do
    info = Util.json_parse(request.body, :down)
    if oldpwd = info['oldpassword']
      return unless valid_token("password.write")
      return not_found(match[1]) unless user = server.scim.get(match[1], :user, :password)
      return bad_request("old password does not match") unless oldpwd == user[:password]
    else
      return unless valid_token("scim.write")
    end
    return bad_request("no new password given") unless newpwd = info['password']
    server.scim.set_hidden_attr(match[1], :password, newpwd)
    reply.json(status: "ok", message: "password updated")
  end

  route :get, %r{^/ids/Users(\?|$)(.*)} do
    page_query(:user, Util.decode_form(match[2], :down), [:username, :id])
  end

end

class StubUAA < Stub::Server

  attr_accessor :reply_badly
  attr_reader :scim, :auto_groups

  def initialize(options = {})
    client = options[:boot_client] || "admin"
    secret = options[:boot_secret] || "adminsecret"
    @scim = StubScim.new
    @auto_groups = ["password.write", "openid"]
        .each_with_object([]) { |g, o| o << @scim.add(:group, 'displayname' => g) }
    ["scim.read", "scim.write", "scim.me", "uaa.resource"]
        .each { |g| @scim.add(:group, 'displayname' => g) }
    gids = ["clients.write", "clients.read", "clients.secret", "uaa.admin"]
        .each_with_object([]) { |s, o| o << @scim.add(:group, 'displayname' => s) }
    @scim.add(:client, 'client_id' => client, 'client_secret' => secret,
        'authorized_grant_types' => ["client_credentials"], 'authorities' => gids,
        'access_token_validity' => 60 * 60 * 24 * 7)
    @scim.add(:client, 'client_id' => "cf", 'authorized_grant_types' => ["implicit"],
        'scope' => [@scim.id("openid", :group), @scim.id("password.write", :group)],
        'access_token_validity' => 5 * 60 )
    info = { commit_id: "not implemented",
        app: {name: "Stub UAA", version: CLI_VERSION,
            description: "User Account and Authentication Service, test server"},
        prompts: {username: ["text", "Username"], password: ["password","Password"]} }
    super(StubUAAConn, options.merge(info: info, logger: options[:logger] || Util.default_logger))
  end

end

end


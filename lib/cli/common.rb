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

require 'cli/base'
require 'cli/config'
require 'uaa'

module CF::UAA

class CommonCli < Topic

  def trace?; opts[:trace] end
  def debug?; opts[:debug] end

  def auth_header
    unless (ttype = Config.value(:token_type)) && (token = Config.value(:access_token))
      raise "Need an access token to complete this command. Please login."
    end
    "#{ttype} #{token}"
  end

  def username(name); name || ask("User name") end
  def userpwd(pwd = opts[:password]); pwd || ask_pwd("Password") end
  def passcode(passcode = opts[:passcode]); passcode || ask("Passcode (from #{Config.target}/passcode)") end
  def clientid(id = opts[:client]); id || ask("Client ID") end
  def clientsecret(secret = opts[:secret]); secret || ask_pwd("Client secret") end
  def clientname(name = opts[:name]); name end

  def verified_pwd(prompt, pwd = nil)
    while pwd.nil?
      pwd_a = ask_pwd prompt
      pwd_b = ask_pwd "Verify #{prompt.downcase}"
      pwd = pwd_a if pwd_a == pwd_b
    end
    pwd
  end

  def askd(prompt, defary)
    return ask(prompt) unless defary
    result = ask("#{prompt} [#{Util.strlist(defary)}]")
    result.nil? || result.empty? ? defary : result
  end

  def complain(e)
    case e
    when TargetError then gripe "\n#{e.message}:\n#{Util.json_pretty(e.info)}"
    when Exception
      gripe "\n#{e.class}: #{e.message}\n\n"
      gripe e.backtrace if trace?
    when String then gripe e
    else gripe "unknown type of gripe: #{e.class}, #{e}"
    end
  end

  def handle_request
    yield
  rescue Exception => e
    complain e
  end

  def scim_request
    yield Scim.new(Config.target, auth_header, {
      skip_ssl_validation: Config.target_value(:skip_ssl_validation),
      ssl_ca_file: Config.target_value(:ca_cert),
      zone: opts[:zone] })
  rescue Exception => e
    complain e
  end

  def update_target_info(info = nil)
    return if !info && Config.target_value(:prompts)
    info ||= @cli_class.uaa_info_client.server
    Config.target_opts(prompts: info['prompts'])
    Config.target_opts(token_endpoint: info['token_endpoint']) if info['token_endpoint']
    info
  end

  def scim_common_list(type, filter)
    pp scim_request { |sr|
      query = { attributes: opts[:attrs], filter: filter }
      info = nil
      if type == :user
        info = sr.query(type, query.merge!(startIndex: opts[:start], count: opts[:count]))
      else
        info = opts[:start] || opts[:count] ?
               sr.query(type, query.merge!(startIndex: opts[:start], count: opts[:count])):
               sr.all_pages(type, query)
      end

      nattr = sr.name_attr(type).downcase
      info.is_a?(Array) && info.length > 0 && info[0][nattr] ?
          info.each_with_object({}) { |v, h| h[v.delete(nattr)] = v } : info
    }
  end

  def scim_get_object(scim, type, name, attrs = nil)
    query = { attributes: attrs, filter: "#{scim.name_attr(type)} eq \"#{name}\""}
    info = scim.all_pages(type, query)
    raise BadResponse unless info.is_a?(Array) && info.length < 2
    raise NotFound if info.length == 0
    info = info[0]
    # when getting whole object, handle case of UAA < 1.3 which did not return meta attr from query
    attrs || !info["id"] || info["meta"]? info : scim.get(type, info["id"])
  end
end

class MiscCli < CommonCli

  topic "Miscellaneous", "misc"

  desc "version", "Display version" do
    say "UAA client #{CLI_VERSION}"
  end

  define_option :trace, "--[no-]trace", "-t", "display extra verbose debug information"
  define_option :debug, "--[no-]debug", "-d", "display debug information"
  define_option :help, "--[no-]help", "-h", "display helpful information"
  define_option :version, "--[no-]version", "-v", "show version"
  define_option :config, "--config [string|file]", "file to get/save configuration information or yaml string"
  define_option :zone, "-z", "--zone <subdomain>", "subdomain of zone to manage"

  desc "help [topic|command...]", "Display summary or details of command or topic" do |*args|
    # handle hidden command, output commands in form for bash completion
    return say_commands if args.length == 1 && args[0] == "commands"
    args.empty? ? say_help : say_command_help(args)
  end

  def normalize_url(url, scheme = nil)
    url = url.strip.gsub(/\/*$/, "")
    raise ArgumentError, "invalid whitespace in target url" if url =~ /\s/
    unless url =~ /^https?:\/\//
      return unless scheme
      url = "#{scheme}://#{url}"
    end
    url = URI.parse(url)
    url.host.downcase!
    url.to_s.to_sym
  end

  def bad_uaa_url(url, info, skip_ssl_validation = false, ca_cert = nil)
    info.replace(@cli_class.uaa_info_client(url.to_s, skip_ssl_validation, ca_cert).server)
    nil
  rescue Exception => e
    "failed to access #{url}: #{e.message}"
  end

  define_option :ca_cert, "--ca-cert [file]", "use the given CA certificate to validate the target's SSL certificate"
  define_option :skip_ssl_validation, "--skip-ssl-validation", "do not attempt to validate ssl certificate"
  define_option :force, "--[no-]force", "-f", "set even if target does not respond"
  desc "target [uaa_url]", "Display current or set new target", :force, :ca_cert, :skip_ssl_validation do |uaa_url|
    msg, info = nil, {}
    if uaa_url
      if uaa_url.to_i.to_s == uaa_url
        return gripe "invalid target index" unless url = Config.target?(uaa_url.to_i)
      elsif url = normalize_url(uaa_url)
        return gripe msg if (msg = bad_uaa_url(url, info, opts[:skip_ssl_validation], opts[:ca_cert])) unless opts[:force] || Config.target?(url)
      elsif !Config.target?(url = normalize_url(uaa_url, "https")) &&
            !Config.target?(url = normalize_url(uaa_url, "http"))
        if opts[:force]
          url = normalize_url(uaa_url, "https")
        else
          return gripe msg if msg = bad_uaa_url((url = normalize_url(uaa_url, "https")), info, opts[:skip_ssl_validation], opts[:ca_cert])
        end
      end
      Config.target = url # we now have a canonical url set to https if possible
      Config.target_opts(skip_ssl_validation: true) if opts[:skip_ssl_validation]
      Config.target_opts(ca_cert: opts[:ca_cert])
      update_target_info(info) if info[:prompts]
    end
    return say "no target set" unless Config.target
    return say "\nTarget: #{Config.target}\n\n" unless Config.context
    say "\nTarget: #{Config.target}\nContext: #{Config.context}, from client #{Config[:client_id]}\n\n"
  end

  desc "targets", "Display all targets" do
    cfg = Config.config
    return say "\nno targets\n" if cfg.empty?
    cfg.each_with_index { |(k, v), i| pp "#{i} #{v[:current] ? '*' : ' '} #{k}" }
    say "\n"
  end

  def config_pp(tgt = nil, ctx = nil)
    Config.config.each_with_index do |(k, v), i|
      next if tgt && tgt != k
      say ""
      splat = v[:current] ? '*' : ' '
      pp "[#{i}]#{splat}[#{k}]"
      v.each {|tk, tv| pp(tv, 2, terminal_columns, tk) unless [:contexts, :current, :prompts].include?(tk)}
      next unless v[:contexts]
      v[:contexts].each_with_index do |(sk, sv), si|
        next if ctx && ctx != sk
        say ""
        splat = sv[:current] && v[:current]? '*' : ' '
        sv.delete(:current)
        pp "[#{si}]#{splat}[#{sk}]", 2
        pp sv, 4, 0
      end
    end
    say ""
  end

  desc "context [name]", "Display or set current context" do |ctx|
    ctx = ctx.to_i if ctx.to_i.to_s == ctx
    Config.context = ctx if ctx && Config.valid_context(ctx)
    (opts[:trace] ? Config.add_opts(trace: true) : Config.delete_attr(:trace)) if opts.key?(:trace)
    return say "no context set in target #{Config.target}" unless Config.context
    config_pp Config.target, Config.context
  end

  desc "contexts", "Display all contexts" do config_pp end

end

end

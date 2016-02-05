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

module CF::UAA

class ClientCli < CommonCli

  topic "Client Application Registrations", "reg"

  CLIENT_SCHEMA = {
      :name => "string",
      :scope => "list",
      :authorized_grant_types => "list",
      :authorities => "list",
      :access_token_validity => "seconds",
      :refresh_token_validity => "seconds",
      :redirect_uri => "list",
      :autoapprove => "list",
      :'signup_redirect_url' => "url"
  }
  CLIENT_SCHEMA.each { |k, v| define_option(k, "--#{k} <#{v}>") }

  def client_info(defaults)
    info = {client_id: defaults[:client_id] || opts[:client_id]}
    info[:client_secret] = opts[:secret] if opts[:secret]
    del_attrs = Util.arglist(opts[:del_attrs], [])
    CLIENT_SCHEMA.each_with_object(info) do |(k, p), info|
      next if del_attrs.include?(k)
      default = Util.strlist(defaults[k])
      if opts.key?(k)
        info[k] = opts[k].nil? || opts[k].empty? ? default : opts[k]
      else
        info[k] = opts[:interact] ?
          info[k] = askd("#{k.to_s.gsub('_', ' ')} (#{p})", default): default
      end
      if k == :autoapprove && (info[k] == "true" || info[k] == "false")
        info[k] = !!(info[k] == "true")
      else
        info[k] = Util.arglist(info[k]) if p == "list"
        info.delete(k) unless info[k]
      end
    end
  end

  desc "clients [filter]", "List client registrations", :attrs, :start, :count do |filter|
    scim_common_list(:client, filter)
  end

  desc "client get [id]", "Get specific client registration", :attrs do |id|
    pp scim_request { |sr| scim_get_object(sr, :client, clientid(id), opts[:attrs]) }
  end

  define_option :clone, "--clone <other>", "get default settings from other"
  define_option :interact, "--[no-]interactive", "-i", "interactively verify all values"
  desc "client add [id]", "Add client registration",
      *CLIENT_SCHEMA.keys, :clone, :secret, :interact do |id|
    pp scim_request { |cr|
      opts[:client_id] = clientid(id)
      opts[:name] = clientname() || opts[:client_id]
      opts[:secret] = verified_pwd("New client secret", opts[:secret])
      defaults = opts[:clone] ? Util.hash_keys!(cr.get(:client, opts[:clone]), :sym) : {}
      defaults.delete(:client_id)
      cr.add(:client, client_info(defaults))
    }
  end

  desc "client update [id]", "Update client registration", *CLIENT_SCHEMA.keys,
      :del_attrs, :interact do |id|
    pp scim_request { |cr|
      opts[:client_id] = clientid(id)
      orig = Util.hash_keys!(cr.get(:client, opts[:client_id]), :sym)
      info = client_info(orig)
      info.any? { |k, v| v != orig[k] } ? cr.put(:client, info) :
          gripe("Nothing to update. Use -i for interactive update.")
    }
  end

  desc "client delete [id]", "Delete client registration" do |id|
    pp scim_request { |cr|
      cr.delete(:client, clientid(id))
      "client registration deleted"
    }
  end

  desc "secret set [id]", "Set client secret", :secret do |id|
    pp scim_request { |cr|
      cr.change_secret(clientid(id), verified_pwd("New secret", opts[:secret]))
      "client secret successfully set"
    }
  end

  define_option :old_secret, "--old_secret <secret>", "current secret"
  desc "secret change", "Change secret for authenticated client in current context", :old_secret, :secret do
    return gripe "context not set" unless client_id = Config.context.to_s
    scim_request { |cr|
      old = opts[:old_secret] || ask_pwd("Current secret")
      cr.change_secret(client_id, verified_pwd("New secret", opts[:secret]), old)
      "client secret successfully changed"
    }
  end

end

end


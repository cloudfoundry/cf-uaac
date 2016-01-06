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
require 'uaa'

module CF::UAA

class InfoCli < CommonCli

  topic "System Information", "sys", "info"

  def misc_request(&blk) Config.target ? handle_request(&blk) : gripe("target not set") end

  desc "info", "get information about current target" do
    pp misc_request { update_target_info(@cli_class.uaa_info_client.server) }
  end

  desc "me", "get authenticated user information" do
    pp misc_request { @cli_class.uaa_info_client.whoami(auth_header) }
  end

  desc "prompts", "Show prompts for credentials required for implicit grant post" do
    pp misc_request { update_target_info(@cli_class.uaa_info_client.server)['prompts'] }
  end

  desc "signing key", "get the UAA's token signing key(s)", :client, :secret do
    info = misc_request {
      @cli_class.uaa_info_client.validation_key(
          (clientid if opts.key?(:client)),
          (clientsecret if opts.key?(:client))
      )
    }
    if info && info['value']
      Config.target_opts(signing_alg: info['alg'], signing_key: info['value'])
    end
    pp info
  end

  desc "stats", "Show UAA's current usage statistics", :client, :secret do
    pp misc_request { @cli_class.uaa_info_client.varz(clientid, clientsecret) }
  end

  desc "password strength [password]", "calculate strength score of a password" do |pwd|
    pp misc_request { @cli_class.uaa_info_client.password_strength(userpwd(pwd)) }
  end

end

end

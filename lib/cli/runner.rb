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
require 'cli/token'
require 'cli/user'
require 'cli/group'
require 'cli/info'
require 'cli/client_reg'
require 'cli/curl'

module CF::UAA

class Cli < BaseCli
  @overview = "UAA Command Line Interface"
  @topics = [MiscCli, InfoCli, TokenCli, UserCli, GroupCli, ClientCli, CurlCli]
  @global_options = [:help, :version, :debug, :trace, :config, :zone]

  def self.configure(config_file = "", input = $stdin, output = $stdout,
      print_on_trace = false)
    @config_file, @input, @output = config_file, input, output
    @print_on_trace = print_on_trace
    self
  end

  def self.handle_bad_command(args, msg)
    @output.puts "\n#{msg}"
    run args.unshift("help")
    nil
  end

  def self.preprocess_options(args, opts)
    return args.replace(["version"]) if opts[:version]
    return args.unshift("help") if args.empty? || opts[:help] && args[0] != "version"
    Config.load(opts[:config] || @config_file) if opts.key?(:config) || !Config.loaded?
    [:trace, :debug].each do |k|
      opts[k] = true if !opts.key?(k) && Config.target && Config.context && Config.value(k)
    end

    @uaa_logger = Util.default_logger(opts[:trace]? :trace: opts[:debug]? :debug: :warn, @output)
  end

  def self.uaa_info_client(url = Config.target, skip_ssl_validation = false, ca_cert = nil)
    if Config.config[url]
      skip_ssl_validation = Config.config[url][:skip_ssl_validation]
      ca_cert = Config.config[url][:ca_cert]
    end
    client = Info.new(url, { skip_ssl_validation: skip_ssl_validation, ssl_ca_file: ca_cert })
    client.logger = @uaa_logger
    client
  end

end

end

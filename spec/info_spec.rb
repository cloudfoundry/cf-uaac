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

require 'spec_helper'
require 'uaac_cli'
require 'stub/uaa'

module CF::UAA

describe InfoCli do

  include SpecHelper

  before :all do
    #Util.default_logger(:trace)
    Cli.configure("", nil, StringIO.new, true)
    if ENV["UAA_CLIENT_TARGET"]
      @target, @stub_uaa = ENV["UAA_CLIENT_TARGET"], nil
      @varz_secret = ENV['UAA_VARZ_SECRET']
    else
      @stub_uaa = StubUAA.new.run_on_thread
      @target, @varz_secret = @stub_uaa.url, "varzsecret"
    end
    Cli.run("target #{@target}").should be
    Cli.output.string.should include URI.parse(@target).host
  end

  after :all do @stub_uaa.stop if @stub_uaa end

  it "gets server info" do
    Cli.run("info").should be
    Cli.output.string.should match /\d.\d.\d/
    Cli.output.string.should include "prompts", "commit_id"
  end

  it "gets prompts" do
    Cli.run("prompts").should be
    Cli.output.string.should include "username", "password"
  end

  it "checks password strength" do
    Cli.run("password strength PaSsW0rd").should be
    Cli.output.string.should include "score", "requiredScore"
  end

  it "gets the server stats" do
    pending "no UAA_VARZ_SECRET environment variable set" unless @varz_secret
    Cli.run("stats -c varz -s #{@varz_secret}").should be
    Cli.output.string.should include 'type: UAA', 'mem:', 'version:'
  end

  it "sets multiple targets to be fully qualified in config and targets output" do
    Config.load("")
    Cli.run("target example1.com --force")
    Cli.run("target example2.com --force")
    Cli.run("target example.com")
    Cli.output.string.should_not include "http://example.com"
    Cli.run("targets").should be
    Config.yaml.should include "https://example1.com", "https://example2.com"
    Cli.output.string.should include "https://example1.com", "https://example2.com"
  end

end
end

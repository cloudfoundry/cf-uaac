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
require 'stringio'
require 'uaac_cli'

module CF::UAA

describe CommonCli do

  include SpecHelper

  before :each do
    # Util.default_logger(:trace)
    Cli.configure("", nil, StringIO.new, true)
  end

  ["-v", "version", "--version"].each do |opt|
    it "displays a version with #{opt}" do
      Cli.run(opt).should be
      Cli.output.string.should include CLI_VERSION
    end
  end

  ["help", "-h"].each do |opt|
    it "displays general help with #{opt}" do
      Cli.run(opt).should be
      ["UAA Command Line Interface", "System Information", "Tokens", "User Accounts"].each do |s|
        Cli.output.string.should include s
      end
    end
  end

  it "gets commands in bash completion format" do
    Cli.run("help commands").should be
    [/--no-version/, /--version/, /^#{File.basename($0)}/, /help/].each do |s|
      Cli.output.string.should match(s)
    end
  end

  ["help targets", "targets -h", "-h targets"].each do |opt|
    it "displays command specific help like: #{opt}" do
      Cli.run(opt).should be
      Cli.output.string.should include("Display all targets")
    end
  end

  it "sets a target in the config file" do
    Cli.run("target example.com --force").should be
    Config.yaml.should include "https://example.com"
  end

  it "strips trailing / from target" do
    Cli.run("target example.com/uaa/ --force")
    Config.yaml.should include "https://example.com/uaa"
    Config.yaml.should_not include "https://example.com/uaa/"
  end

  it "sets multiple targets to be forced qualified in config and targets output" do
    Cli.run("target example.com --force")
    Cli.run("target example2.com --force")
    Cli.run("targets").should be
    Config.yaml.should include "https://example.com", "https://example2.com"
    Cli.output.string.should include "https://example.com", "https://example2.com"
  end

  it "gets it's configuration from alternate source when specified" do
    Cli.run("target --force foo.bar --config").should be
    Config.yaml.should include "foo\.bar"
    Cli.run "target --force baz.com --config"
    Config.yaml.should include "baz\.com"
    Config.yaml.should_not include "foo\.bar"
  end

  it "does not attempt to validate ssl certificate" do
    Cli.run("target --force --skip-ssl-validation https://example.com")
    Cli.output.string.should include "https://example.com"
    Config.yaml.should include "skip_ssl_validation: true"
  end

  it "accepts a root CA as a commandline parameter" do
    Cli.run("target --force --ca-cert dir/rootCA.pem https://example.com")
    Cli.output.string.should include "https://example.com"
    Config.yaml.should include "ca_cert: dir/rootCA.pem"
  end

  it "only attempts http if scheme is http" do
    Cli.run("target http://example.com")
    puts Cli.output.string
    Cli.output.string.should_not include "https"
  end

end
end


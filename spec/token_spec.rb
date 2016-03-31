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

module CF::UAA

describe TokenCli do

  include SpecHelper

  before :all do
    #Util.default_logger(:trace)
    Cli.configure("", nil, StringIO.new, true)
    setup_target(authorities: "clients.read,scim.read,scim.write,uaa.resource")
    Cli.run("token client get #{@test_client} -s #{@test_secret}").should be
    Config.yaml.should include("access_token")
    @test_pwd_unescaped = "@~`!$@%#%^$^&*)(|}{[]\":';?><,./"
    @test_pwd = Shellwords.escape(@test_pwd_unescaped)
    @test_user = "test_user_#{Time.now.to_i}"
    Cli.run("user add #{@test_user} -p #{@test_pwd} " +
        "--emails sam@example.com,joNES@sample.com --given_name SamueL " +
        "--phones 801-555-1212 --family_name jonES").should be
  end

  after :all do
    Cli.run "context #{@test_client}"
    Cli.run("user delete #{@test_user}").should be
    Cli.run("user get #{@test_user}").should be_nil
    cleanup_target
  end

  it "logs in with implicit grant & posted credentials as a user" do
    Cli.run("token get #{@test_user} #{@test_pwd}").should be
    Cli.output.string.should include("Successfully fetched token")
    Cli.run("context")
    Cli.output.string.should match /scope:.+password\.write openid.*$/
  end

  it "can request a specific scope" do
    Cli.run("token delete")
    Cli.output.truncate 0
    Cli.run("token get --scope password.write #{@test_user} #{@test_pwd}").should be
    Cli.output.string.should include("Successfully fetched token")
    Cli.run("context")
    Cli.output.string.should match /scope: password\.write$/
  end

  it "decodes the token" do
    Cli.run("token decode").should be
    ["user_name", "exp", "aud", "scope", "client_id", "email", "user_id"].each do |a|
      Cli.output.string.should include(a)
    end
    Cli.output.string.should include("email: sam@example.com")
    Cli.output.string.should include("user_name: #{@test_user}")
  end

  it "gets authenticated user information" do
    Cli.run("token get #{@test_user} #{@test_pwd}").should be
    Cli.run("me").should be
    Cli.output.string.should include(@test_user)
  end

  it "updates the user" do
    Cli.run "context #{@test_client}"
    Cli.run("user update #{@test_user} --emails #{@test_user}+1@example.com --phones 123-456-7890").should be
    Cli.run("user get #{@test_user}").should be
    Cli.output.string.should include(@test_user, "#{@test_user}+1@example.com", "123-456-7890")
  end

  it "gets updated information in the token" do
    Cli.run("token get #{@test_user} #{@test_pwd}").should be
    Cli.output.string.should include("Successfully fetched token")
    Cli.run("token decode").should be
    Cli.output.string.should include("email: #{@test_user}+1@example.com")
  end

  it "gets ids for a username" do
    Cli.run("user ids #{@test_user.downcase}").should be
    Cli.output.string.should include(@test_user, "id")
  end

  it "has multiple distinct authentication contexts" do
    Cli.run("contexts").should be
    Cli.output.string.should include "[admin]", "[#{@test_client}]", "[#{@test_user.downcase}]"
  end

  it "removes the user context" do
    Cli.run("token delete #{@test_user}").should be
    Cli.run "contexts"
    Cli.output.string.should include "[admin]", "[#{@test_client}]"
    Cli.output.string.should_not include "#{@test_user}"
  end

  it "logs in with owner password grant" do
    Cli.run("token owner get #{@test_client} -s #{@test_secret} #{@test_user} -p #{@test_pwd}" ).should be
    Cli.output.string.should include "Successfully fetched token"
  end

  it "logs in with sso passcode grant" do
    fakePasscode = Base64::urlsafe_encode64("#{@test_user} #{@test_pwd_unescaped}")
    cli_run = Cli.run("token sso get #{@test_client} -s #{@test_secret} --passcode #{fakePasscode}")
    cli_run.should be
    Cli.output.string.should include "Successfully fetched token"
  end

  it "decodes the owner token" do
    Cli.run("token decode").should be
    ["user_name", "exp", "aud", "scope", "client_id", "email", "user_id", "openid", "password.write"].each do |a|
      Cli.output.string.should include a
    end
  end

  it "gets the server signing key" do
    Cli.run("signing key -c #{@test_client} -s #{@test_secret}").should be
    Cli.output.string.should include 'alg:', 'value:'
  end

  it "uses the token endpoint given by the login server" do
    pending "only saml login server returns token endpoint" if ENV["UAA_CLIENT_TARGET"]
    @stub_uaa.info[:token_endpoint] = te = "#{@stub_uaa.url}/alternate"
    Cli.run("target #{@target} --config")
    Cli.run("token client get #{@test_client} -s #{@test_secret}").should be
    Config.yaml.should include("access_token", "token_endpoint", te)
    @stub_uaa.info[:token_endpoint].should be_nil
    Cli.configure("", nil, StringIO.new) # clean up
    Cli.run("target #{@target}").should be
    Cli.run("token client get #{@admin_client} -s #{@admin_secret}").should be
  end

end

end

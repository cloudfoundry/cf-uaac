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

describe ClientCli do

  include SpecHelper

  before :all do
    #Util.default_logger(:trace)
    @output = StringIO.new
    Cli.configure("", nil, @output, true)
    setup_target(authorities: "scim.read,clients.secret", grant_types: "client_credentials")
    @test_user, @test_pwd = "sam_#{Time.now.to_i}", "correcthorsebatterystaple"
  end

  after :all do cleanup_target end

  it "registers a new client" do
    @test_client.should be # actually registered in the before :all block
  end

  it "gets a client registration" do
    Cli.run("client get #{@test_client}").should be
    Cli.output.string.should include @test_client
  end

  it "lists client registrations" do
    Cli.run("clients").should be
    Cli.output.string.should include @admin_client, @test_client
  end

  context "as test client" do

    before :all do
      Cli.run("token client get #{@test_client} -s #{@test_secret}").should be
    end

    it "logs in as test client" do
      Cli.run("context").should be # login was in before :all block
      Cli.output.string.should include @test_client
      Cli.output.string.should match /access_token: \S+?\s+token_type/m
    end

    it "does not wrap the output of the access token in the terminal" do
      @output.stub(:tty?) { true }
      HighLine::SystemExtensions.stub(:terminal_size) { [80] }
      Cli.run("context").should be
      Cli.output.string.should match /access_token: \S+?\s+token_type/m
    end

    it "changes it's client secret" do
      Cli.run("token client get #{@test_client} -s #{@test_secret}").should be
      Cli.run("token decode").should be
      Cli.run("secret change --old_secret #{@test_secret} --secret newclientsecret").should be
      Cli.run("token client get #{@test_client} -s newclientsecret").should be
      Cli.run("secret change --old_secret newclientsecret -s #{@test_secret}").should be
      Cli.run("token client get #{@test_client} -s #{@test_secret}").should be
    end

    it "fails to create a user account as test client" do
      Cli.run("user add #{@test_user} -p #{@test_pwd}").should be_nil
      Cli.output.string.should include "access_denied"
    end

    context "as updated client" do

      before :all do
        # update the test client as the admin client
        Cli.run("token client get #{@test_client} -s #{@test_secret}").should be
        Cli.run("context #{@admin_client}").should be
        Cli.run("client update #{@test_client} --authorities scim.write,scim.read").should be
        Cli.run("client get #{@test_client}").should be
        Cli.output.string.should include "scim.read", "scim.write"
      end

      it "fails to create a user account with old token" do
        Cli.run("context #{@test_client}").should be
        Cli.run("user add #{@test_user} -p #{@test_pwd}").should be_nil
        Cli.output.string.should include "access_denied"
      end

      it "creates a user account with a new token" do
        Cli.run("context #{@test_client}").should be
        Cli.run("token client get #{@test_client} -s #{@test_secret}").should be
        Cli.run("token decode")
        Cli.run("user add #{@test_user.capitalize} -p #{@test_pwd} --email #{@test_user}@example.com --family_name #{@test_user.capitalize} --given_name joe").should be
        Cli.output.string.should_not include "access_denied"
        Cli.run("user get #{@test_user}").should be
        Cli.output.string.should include @test_user.capitalize
      end
    end

  end

#  context "as admin client" do
#    it "deletes a client registration" do
#      client = @test_client.dup
#      @test_client.replace("")
#      Cli.run("context #{@admin_client}").should be
#      Cli.run("client delete #{client}").should be
#      Cli.output.string.should include "deleted"
#    end
#  end

end

end

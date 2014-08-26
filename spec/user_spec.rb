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

describe UserCli do

  include SpecHelper

  before :all do
    #Util.default_logger(:trace)
    Cli.configure("", nil, StringIO.new, true)
    setup_target(authorities: "clients.read,scim.read,scim.write")
    Cli.run("token client get #{@test_client} -s #{@test_secret}").should be
    Config.yaml.should include("access_token")
    @test_pwd = "TesTpwd$%^"
    @test_user = "tEst_UseR_#{Time.now.to_i}"
    Cli.run("user add #{@test_user} -p #{@test_pwd} " +
        "--emails sam@example.com,joNES@sample.com --given_name SamueL " +
        "--phones 801-555-1212 --family_name jonES").should be
  end

  after :all do
    Cli.run("user delete #{@test_user}")
    cleanup_target
  end

  it "creates a user" do
    Cli.output.string.should include "success"
  end

  it "fails to change a user's password with the wrong old pwd" do
    Cli.run("password change -p newpwd --old_password not-the-password").should be_nil
  end

  it "changes a user's password" do
    Cli.run("token get #{@test_user} #{@test_pwd}").should be
    Cli.run("password change --password newpwd --old_password #{@test_pwd}").should be
    Cli.run("token get #{@test_user} newpwd").should be
    Cli.run("password change -p #{@test_pwd} -o newpwd").should be
    Cli.run("token get #{@test_user} #{@test_pwd}").should be
    Cli.output.string.should include "Successfully fetched token"
  end

  it "preserves case in names" do
    Cli.run("context #{@test_client}")
    Cli.run("user get #{@test_user.upcase}").should be
    Cli.output.string.should =~ /#{@test_user}/
  end

  describe "get list of users" do
    before :all do
      i = 1
      count = 15
      while i < count  do
        Cli.run("user add user-#{i} -p password-#{i} " +
                    "--emails user-#{i}@example.com --given_name user#{i} " +
                    "--phones 801-555-243#{i} --family_name jonES")
        i +=1
      end
    end

    after :all do
      i = 1
      count = 15
      while i < count  do
        Cli.run("user delete user-#{i}")
        i +=1
      end
    end

    it "gets users with default pagination" do
      Cli.run("users")
      Cli.output.string.should include "user-1"
      Cli.output.string.should include "user-2"
      Cli.output.string.should include "user-14"
      # Default page size for stub uaa is 15
      Cli.output.string.should_not include "user-15"
    end

    it "gets count users with pagination" do
      Cli.run("users --start 1 --count 3")
      Cli.output.string.should include "user-1"
      Cli.output.string.should include "user-2"
      Cli.output.string.should_not include "user-3"
    end
  end

end

end

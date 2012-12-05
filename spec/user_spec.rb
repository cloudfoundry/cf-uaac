#--
# Cloud Foundry 2012.02.03 Beta
# Copyright (c) [2009-2012] VMware, Inc. All Rights Reserved.
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
require 'cli'

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

  after :all do cleanup_target end

  it "creates a user" do
    Cli.output.string.should include "success"
  end

  it "fails to change a user's password with the wrong old pwd" do
    Cli.run("password change -p newpwd --old_password not-the-password").should be_nil
  end

  it "changes a user's password" do
    Cli.run("token get #{@test_user} #{@test_pwd}").should be
    Cli.run("password change -p newpwd --old_password #{@test_pwd}").should be
    Cli.run("token get #{@test_user} newpwd").should be
    Cli.output.string.should include "Successfully fetched token"
  end

  it "preserves case in names" do
    Cli.run("context #{@test_client}")
    Cli.run("user get #{@test_user.upcase}").should be
    Cli.output.string.should =~ /#{@test_user}/
  end

end

end

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

describe GroupCli do

  include SpecHelper

  before :all do
    #Util.default_logger(:trace)
    Cli.configure("", nil, StringIO.new, true)
    setup_target(authorities: "clients.read,scim.read,scim.write")
    Cli.run("token client get #{@test_client} -s #{@test_secret}").should be
    @test_user, @test_pwd = "sam_#{Time.now.to_i}", "correcthorsebatterystaple"
    @test_group = "JaNiToRs_#{Time.now.to_i}"
  end

  after :all do cleanup_target end
  before :each do Cli.output.string = "" end

  it "creates many users and a group as the test client" do
    Cli.run "context #{@test_client}"
    Cli.run("user add #{@test_user.upcase} -p #{@test_pwd} " +
        "--email joey@example.com --family_name JONES --given_name JOE").should be
    29.times { |i| Cli.run("user add #{@test_user.capitalize}-#{i} -p #{@test_pwd} " +
        "--email #{@test_user}+#{i}@example.com " +
        "--family_name #{@test_user.capitalize} --given_name joe").should be }
    Cli.run("group add #{@test_group}").should be
    Cli.run("groups -a displayName").should be
    Cli.output.string.should include @test_group
  end

  it "gets attributes with case-insensitive attribute names" do
    Cli.run("groups -a displayname").should be
    Cli.output.string.should include @test_group
  end

  it "lists all users" do
    Cli.run("users -a UsernamE").should be
    29.times { |i| Cli.output.string.should =~ /#{@test_user.capitalize}-#{i}/i }
  end

  it "preserves case in names" do
    Cli.run("users -a username").should be
    29.times { |i| Cli.output.string.should =~ /#{@test_user.capitalize}-#{i}/ }
  end

  it "lists a page of users" do
    Cli.run("users -a userName --count 13 --start 5").should be
    Cli.output.string.should match /itemsPerPage: 13/i
    Cli.output.string.should match /startIndex: 5/i
  end

  it "adds users to the group" do
    cmd = "member add #{@test_group}"
    29.times { |i| cmd << " #{@test_user.capitalize}-#{i}" }
    Cli.run(cmd).should be
    Cli.output.string.should include "success"
  end

  it "adds one user to the group" do
    Cli.run("member add #{@test_group} #{@test_user}").should be
    Cli.output.string.should include "success"
  end

  it "deletes all members from a group" do
    pending "waiting on bug fix in uaa, [40594865]" if ENV["UAA_CLIENT_TARGET"]
    cmd = "member delete #{@test_group} #{@test_user.capitalize}"
    29.times { |i| cmd << " #{@test_user.capitalize}-#{i}" }
    Cli.run(cmd).should be
    Cli.output.string.should include "success"
    # and they should really be gone
    Cli.run("group get #{@test_group}")
    Cli.output.string.should_not match /members/i
  end

end

end

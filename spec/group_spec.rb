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

describe GroupCli do

  include SpecHelper

  before :all do
    #Util.default_logger(:trace)
    Cli.configure("", nil, StringIO.new, true)
    setup_target(authorities: "clients.read,scim.read,scim.write,uaa.admin")
    Cli.run("token client get #{@test_client} -s #{@test_secret}").should be
    @test_user, @test_pwd = "SaM_#{Time.now.to_i}_", "correcthorsebatterystaple"
    @test_group = "JaNiToRs_#{Time.now.to_i}"
    @users = ["w", "r", "m", "n"].map { |v| @test_user + v }
    5.times { |i| @users << @test_user + i.to_s }
    @users.each { |u| Cli.run("user add #{u} -p #{@test_pwd} --email sam@example.com").should be }
    Cli.run("group add #{@test_group}").should be
    Cli.run("groups -a displayName").should be
    Cli.output.string.should include @test_group
  end

  after :all do
    Cli.run "context #{@test_client}"
    @users.each { |u| Cli.run("user delete #{u}") }
    @users.each { |u| Cli.run("user get #{u}").should be_nil }
    Cli.run("group delete #{@test_group}").should be
    cleanup_target
  end

  # actual user and group creation happens in before_all
  it "creates many users and a group as the test client" do
    @users.each { |u|
      Cli.run("user get #{u}").should be
      Cli.output.string.should include u
    }
    @users.each { |u| Cli.run("member add scim.me #{u}").should be }
    Cli.run("groups -a displayName").should be
    Cli.output.string.should include @test_group
    Cli.run("group get #{@test_group.upcase}").should be
    Cli.output.string.should include @test_group
    Cli.run("member add scim.read #{@test_user}w").should be
  end

  it "gets attributes with case-insensitive attribute names" do
    Cli.run("groups -a dISPLAYNAME").should be
    Cli.output.string.should include @test_group
  end

  it "lists all users" do
    Cli.run("users -a UsernamE").should be
    @users.each { |u| Cli.output.string.should include u }
  end

  it "lists a page of users" do
    Cli.run("users -a userName --count 4 --start 5").should be
    Cli.output.string.should match /itemsPerPage: 4/i
    Cli.output.string.should match /startIndex: 5/i
  end

  it "adds one user to the group" do
    Cli.run("member add #{@test_group} #{@users[0]}").should be
    Cli.output.string.should include "success"
  end

  it "adds users to the group" do
    cmd = "member add #{@test_group}"
    @users.each { |u| cmd << " #{u.upcase}" }
    Cli.run(cmd).should be
    Cli.output.string.should include "success"
  end

  def check_members
    ids = Cli.output.string.scan(/.*value:\s+([^\s]+)/).flatten
    ids.size.should == @users.size
    @users.each { |u|
      Cli.run("user get #{u} -a id").should be
      Cli.output.string =~ /.*id:\s+([^\s]+)/
      ids.delete($1).should == $1
    }
    ids.should be_empty
  end

  it "lists all group members" do
    Cli.run("group get #{@test_group} -a memBers").should be
    check_members
  end

  it "adds one reader to the group" do
    Cli.run("group reader add #{@test_group} #{@test_user}r").should be
    Cli.output.string.should include "success"
  end

  it "adds one writer to the group" do
    Cli.run("group writer add #{@test_group} #{@test_user}w").should be
    Cli.output.string.should include "success"
  end

  it "gets readers and writers in the group" do
    Cli.run("group get #{@test_group}").should be
    Cli.output.string.should be
  end

  it "reads members as a reader" do
    pending "Test not applicable in integration test runs" if ENV["UAA_CLIENT_TARGET"]

    Cli.run("token owner get #{@test_client} -s #{@test_secret} #{@test_user}r -p #{@test_pwd}").should be
    Cli.run("group get #{@test_group} -a memBers").should be
    ids = Cli.output.string.scan(/.*value:\s+([^\s]+)/).flatten
    @users.size.should == ids.size
  end

  it "can't write members as a reader" do
    Cli.run("token owner get #{@test_client} -s #{@test_secret} #{@test_user}r -p #{@test_pwd}").should be
    Cli.run("member add #{@test_group} #{@test_user}z").should_not be
    Cli.output.string.should include "access_denied"
  end

  it "adds a member as a writer" do
    pending "Test not applicable in integration test runs" if ENV["UAA_CLIENT_TARGET"]

    Cli.run "context #{@test_client}"
    Cli.run("user add #{@test_user}z -p #{@test_pwd} --email sam@example.com").should be
    @users << "#{@test_user}z"
    Cli.run("token owner get #{@test_client} -s #{@test_secret} #{@test_user}w -p #{@test_pwd}").should be
    Cli.run("member add #{@test_group} #{@test_user}z").should be
    Cli.run("group get #{@test_group} -a memBers").should be
    ids = Cli.output.string.scan(/.*value:\s+([^\s]+)/).flatten
    @users.size.should == ids.size
    # check_members
  end

  it "can't read members as a non-reader" do
    pending "real uaa still returns members even if user is not in readers list" unless @stub_uaa
    Cli.run("token owner get #{@test_client} -s #{@test_secret} #{@test_user}m -p #{@test_pwd}").should be
    Cli.run("group get #{@test_group}").should be_nil
    Cli.output.string.should include "NotFound"
  end

  it "deletes all members from a group" do
    Cli.run "context #{@test_client}"
    cmd = "member delete #{@test_group.downcase} "
    @users.each { |u| cmd << " #{u.downcase}" }
    Cli.run(cmd).should be
    Cli.output.string.should include "success"
    Cli.run("group get #{@test_group}")
    Cli.output.string.should_not match /members/i # they should really be gone
  end

  it "does not blow up if scope is invalid" do
    Cli.run("token owner get #{@test_client} -s #{@test_secret} #{@test_user}m -p #{@test_pwd}").should be
    Cli.run "group map ldap-id --name #{@test_group}"
    Cli.run "group mappings"
    Cli.output.string.should_not include "NoMethodError"
  end

  it "lists all the mappings between uaa scopes and external groups" do
    Cli.run "context #{@test_client}"
    Cli.run "group map ldap-id --name #{@test_group}"
    Cli.output.string.should include("Successfully mapped")
    Cli.run "group map ldap-id-2 --name #{@test_group}"
    Cli.output.string.should include("Successfully mapped")
    Cli.run "group mappings"
    Cli.output.string.should include("ldap: \n    -\n      #{@test_group}: ldap-id\n    -\n      #{@test_group}: ldap-id-2")
  end

  it "lists mappings between uaa scopes and external groups with pagination" do
    Cli.run "context #{@test_client}"
    Cli.run("group add new-group")

    Cli.run "group map ldap-id --name #{@test_group}"
    Cli.run "group map ldap-id-2 --name #{@test_group}"
    Cli.run "group map ldap-id --name new-group"
    Cli.run "group map ldap-id-3 --name #{@test_group}"
    Cli.run "group map ldap-id-3 --name new-group"
    Cli.run "group map ldap-id-4 --name #{@test_group}"

    Cli.output.string.should include "Successfully mapped #{@test_group} to ldap-id"

    Cli.run "group mappings"
    Cli.output.string.should include("#{@test_group}: ldap-id")
    Cli.output.string.should include("#{@test_group}: ldap-id-2")
    Cli.output.string.should include("#{@test_group}: ldap-id-3")
    Cli.output.string.should include("#{@test_group}: ldap-id-4")

    Cli.run "group mappings --start 1 --count 3"
    Cli.output.string.should include("#{@test_group}: ldap-id")
    Cli.output.string.should include("#{@test_group}: ldap-id-2")
    Cli.output.string.should include("#{@test_group}: ldap-id-3")
    Cli.output.string.should_not include("ldap-id-4")

    Cli.run "group mappings --start 1 --count -3"
    Cli.output.string.should_not include("ldap-id", "ldap-id-2", "ldap-id-3")
    Cli.output.string.should include("Please enter a valid count")

    Cli.run "group mappings --start 1 --count a"
    Cli.output.string.should_not include("ldap-id", "ldap-id-2", "ldap-id-3")
    Cli.output.string.should include("Please enter a valid count")

    Cli.run "group mappings --start -1 --count 5"
    Cli.output.string.should include("#{@test_group}: ldap-id")
    Cli.output.string.should include("#{@test_group}: ldap-id-2")
    Cli.output.string.should include("#{@test_group}: ldap-id-3")

    Cli.run "group mappings --start a --count 1"
    Cli.output.string.should_not include("ldap-id", "ldap-id-2", "ldap-id-3")
    Cli.output.string.should include("Please enter a valid start index")

    Cli.run "group mappings --start 2"
    Cli.output.string.should include("#{@test_group}: ldap-id-2")
    Cli.output.string.should include("#{@test_group}: ldap-id-3")
    Cli.output.string.should include("#{@test_group}: ldap-id-4")

    Cli.run "group mappings --count 2"
    Cli.output.string.should include("#{@test_group}: ldap-id")
    Cli.output.string.should include("#{@test_group}: ldap-id-2")
  end

  it "maps a uaa scope to an external group" do
    Cli.run "context #{@test_client}"

    Cli.run "group map ldap-id"
    Cli.output.string.should include "Please provide a group name or id"

    Cli.run "group map --name #{@test_group}"
    Cli.output.string.should include "Please provide an external group"

    Cli.run "group map ldap-id --name #{@test_group}"
    Cli.output.string.should include "Successfully mapped #{@test_group} to ldap-id for origin ldap"

    Cli.run "group map ldap-id --name #{@test_group} --origin ldap2"
    Cli.output.string.should include "Successfully mapped #{@test_group} to ldap-id for origin ldap2"

    Cli.run("group get #{@test_group}")
    test_group_id = Cli.output.string.match(/id: ([\S]+)/)[1]
    Cli.run "group map ldap-id --id #{test_group_id}"
    Cli.output.string.should include "Successfully mapped #{@test_group} to ldap-id"
  end

  it "unmaps a uaa scope from an external group" do
    Cli.run "context #{@test_client}"

    Cli.run "group map ldap-id --name #{@test_group}"
    Cli.output.string.should include "Successfully mapped #{@test_group} to ldap-id for origin ldap"

    Cli.run "group map ldap-id --name #{@test_group} --origin ldap2"
    Cli.output.string.should include "Successfully mapped #{@test_group} to ldap-id for origin ldap2"

    Cli.run("group get #{@test_group}")

    Cli.run "group unmap"
    Cli.output.string.should include "Please provide a group name and external group"

    Cli.run "group unmap #{@test_group}"
    Cli.output.string.should include "Please provide a group name and external group"

    Cli.run "group unmap #{@test_group} ldap-id"
    Cli.output.string.should include "Successfully unmapped ldap-id from #{@test_group} for origin ldap"

    Cli.run "group unmap nonexistent_group unmapped_ldap-id"
    Cli.output.string.should include "Group nonexistent_group not found"

    Cli.run "group unmap #{@test_group} ldap-id --origin ldap2"
    Cli.output.string.should include "Successfully unmapped ldap-id from #{@test_group} for origin ldap2"

    Cli.run "group unmap #{@test_group} unmapped_ldap-id"
    Cli.output.string.should include "NotFound"
  end
end

end

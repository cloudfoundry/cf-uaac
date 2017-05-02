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
    Cli.configure('', nil, StringIO.new, true)
    setup_target(authorities: 'clients.read,scim.read,scim.write')
    Cli.run("token client get #{@test_client} -s #{@test_secret}").should be
    Config.yaml.should include('access_token')
    @test_pwd = 'TesTpwd$%^'
    @test_user = "tEst_UseR_#{Time.now.to_i}"
    Cli.run("user add #{@test_user} -p #{@test_pwd} " +
      '--emails sam@example.com --given_name SamueL ' +
      '--phones 801-555-1212 --family_name jonES').should be
  end

  after :all do
    Cli.run("user delete #{@test_user}")
    cleanup_target
  end

  it 'creates a user' do
    Cli.output.string.should include 'success'
  end

  it 'does not set a origin (defaults to uaa through api)' do
    Cli.run("user get #{@test_user.upcase}").should_not include 'origin'
  end

  it 'sets an origin when specified' do
    user_with_origin = "#{@test_user}_with_origin"
    create_user_by_origin( user_with_origin, 'ldap')
    Cli.run("user delete #{user_with_origin}")
  end

  it 'updates origin when specified' do
    user_with_origin = "#{@test_user}_with_origin"
    create_user_by_origin( user_with_origin, 'ldap')

    Cli.run("user update #{user_with_origin} --origin newvalue")
    returned_user = Cli.run("user get #{user_with_origin.upcase}")
    returned_user['origin'].should match 'newvalue'
    Cli.run("user delete #{user_with_origin}")
  end

  it 'gets user when origin specified' do
    user_with_diff_origin = "same_username_with_two_origins"
    create_user_by_origin( user_with_diff_origin, 'ldap')
    create_user_by_origin( user_with_diff_origin, 'saml')

    returned_user = Cli.run("user get #{user_with_diff_origin.upcase} --origin ldap")
    returned_user['origin'].should match 'ldap'
    Cli.run("user delete #{user_with_diff_origin} --origin ldap")
    Cli.run("user delete #{user_with_diff_origin} --origin saml")
  end

  it 'deletes user when origin specified' do
    user_with_diff_origin = "same_username_with_two_origins"
    create_user_by_origin( user_with_diff_origin, 'ldap')
    create_user_by_origin( user_with_diff_origin, 'saml')

    Cli.run("user delete #{user_with_diff_origin.upcase} --origin ldap")
    Cli.output.string.should include 'successfully deleted'
    Cli.run("user delete #{user_with_diff_origin} --origin saml")
  end

  it "fails to change a user's password with the wrong old pwd" do
    Cli.run('password change -p newpwd --old_password not-the-password').should be_nil
  end

  it "changes a user's password" do
    Cli.run("token get #{@test_user} #{@test_pwd}").should be
    Cli.run("password change --password newpwd --old_password #{@test_pwd}").should be
    Cli.run("token get #{@test_user} newpwd").should be
    Cli.run("password change -p #{@test_pwd} -o newpwd").should be
    Cli.run("token get #{@test_user} #{@test_pwd}").should be
    Cli.output.string.should include 'Successfully fetched token'
  end

  it 'preserves case in names' do
    Cli.run("context #{@test_client}")
    Cli.run("user get #{@test_user.upcase}").should be
    Cli.output.string.should =~ /#{@test_user}/
  end

  it 'unlocks a user' do
    Cli.run('user add user-1 -p password-1 ' +
      '--emails user-1@example.com --given_name user1 ' +
      '--phones 801-555-2431 --family_name jonES')
    Cli.run('user unlock user-1')
    Cli.output.string.should include 'success'
    Cli.run('user delete user-1')
  end

  it 'deactivates a user' do
    Cli.run("user deactivate #{@test_user}")
    Cli.output.string.should include 'user account successfully deactivated'
    Cli.run("user get #{@test_user}")
    Cli.output.string.should include 'active: false'
  end

  it 'activates a user' do
    Cli.run("user activate #{@test_user}")
    Cli.output.string.should include 'user account successfully activated'
    Cli.run("user get #{@test_user}")
    Cli.output.string.should include 'active: true'
  end

  def create_user_by_origin(user_name, origin)
  puts "user add #{user_name} -p #{@test_pwd} " +
           '--emails sam@example.com,joNES@sample.com --given_name SamueL ' +
           "--phones 801-555-1212 --family_name jonES --origin #{origin}"
    Cli.run("user add #{user_name} -p #{@test_pwd} " +
                '--emails sam@example.com,joNES@sample.com --given_name SamueL ' +
                "--phones 801-555-1212 --family_name jonES --origin #{origin}").should be
    user_name = Cli.run("user get #{user_name.upcase} --origin #{origin}")
    user_name['origin'].should match origin
    user_name
  end

  describe 'get list of users' do
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

    it 'gets users with default pagination' do
      Cli.run('users')
      Cli.output.string.should include 'user-1'
      Cli.output.string.should include 'user-2'
      Cli.output.string.should include 'user-14'
      # Default page size for stub uaa is 15
      Cli.output.string.should_not include 'user-15'
    end

    it 'gets count users with pagination' do
      Cli.run('users --start 1 --count 3')
      Cli.output.string.should include 'user-1'
      Cli.output.string.should include 'user-2'
      Cli.output.string.should_not include 'user-3'
    end
  end

end

end

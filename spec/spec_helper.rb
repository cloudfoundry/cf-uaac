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

if ENV['COVERAGE']
  require "simplecov"
  if ENV['COVERAGE'] =~ /rcov/
    require "simplecov-rcov"
    SimpleCov.formatter = SimpleCov::Formatter::RcovFormatter
  end
  SimpleCov.add_filter "^#{File.dirname(__FILE__)}" if ENV['COVERAGE'] =~ /exclude-spec/
  SimpleCov.add_filter "^#{File.expand_path(File.join(__FILE__, "..", "..", "vendor"))}" if ENV['COVERAGE'] =~ /exclude-vendor/
  SimpleCov.start
end

require 'rspec'
require 'eventmachine'
require 'stub/uaa'

module CF::UAA

module SpecHelper

  def capture_exception
    yield
  rescue Exception => e
    e
  end

  # Runs given block on a thread or fiber and returns result.
  # If eventmachine is running on another thread, the fiber
  # must be on the same thread, hence EM.schedule and the
  # restriction that the given block cannot include rspec matchers.
  def frequest(on_fiber, &blk)
    return capture_exception(&blk) unless on_fiber
    result, cthred = nil, Thread.current
    EM.schedule { Fiber.new { result = capture_exception(&blk); cthred.run }.resume }
    Thread.stop
    result
  end

  def setup_target(opts = {})
    test_client = "test_client_#{Time.now.to_i}"
    opts = { authorities: "clients.read,scim.read,scim.write,uaa.resource",
      grant_types: "client_credentials,password,refresh_token",
      name: test_client,
      scope: "openid,password.write,scim.me,scim.read",
      autoapprove: "openid,password.write,scim.me,scim.read",
      signup_redirect_url: "home"}.update(opts)
    @admin_client = ENV["UAA_CLIENT_ID"] || "admin"
    @admin_secret = ENV["UAA_CLIENT_SECRET"] || "adminsecret"
    if ENV["UAA_CLIENT_TARGET"]
      @target, @stub_uaa = ENV["UAA_CLIENT_TARGET"], nil
    else
      @stub_uaa = StubUAA.new(boot_client: @admin_client, boot_secret: @admin_secret).run_on_thread
      @target = @stub_uaa.url
    end
    Cli.run("target #{@target}").should be
    Cli.run("token client get #{@admin_client} -s #{@admin_secret}")
    Config.yaml.should include("access_token")
    @test_secret = Shellwords.escape("+=tEsTsEcRet~!@--")
    Cli.run("client add #{test_client} -s #{@test_secret} " +
        "--authorities #{opts[:authorities]} " +
        "--scope #{opts[:scope]} " +
        "--name #{opts[:name]} " +
        "--authorized_grant_types #{opts[:grant_types]} " +
        "--autoapprove #{opts[:autoapprove]} " +
        "--signup_redirect_url #{opts[:signup_redirect_url]}").should be
    opts.each { |k, a| Util.arglist(a).each {|v| Cli.output.string.should include(v) }}
    @test_client = test_client
  end

  def cleanup_target
    #Cli.run "context #{@test_client}"
    #Cli.run("groups"); puts Cli.output.string
    #Cli.run("users"); puts Cli.output.string
    Cli.run("context #{@admin_client}")
    if @test_client && !@test_client.empty?
      Cli.run("client delete #{@test_client}").should be
      Cli.output.string.should include("deleted")
    end
    @stub_uaa.stop if @stub_uaa
  end
end

end


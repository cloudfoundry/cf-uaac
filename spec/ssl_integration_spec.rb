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
require 'fiber'
require 'em-http'
require 'uaac_cli'
require 'stub/server'

module CF::UAA

  if ENV["UAA_CLIENT_TARGET"] && ENV["UAA_CLIENT_TARGET"].start_with?("https")

    class StubHttp < Stub::Base
      route(:get, '/') { reply_in_kind "welcome to stub http, version #{CLI_VERSION}" }
    end

    describe "cf-uaa-lib integration" do

      include SpecHelper

      before :all do
        @url = URI.parse(ENV["UAA_CLIENT_TARGET"])
        Cli.configure("", nil, StringIO.new, true)
      end

      before :each do
        Config.load("")
      end

      describe 'targetting a https URL' do
        it "fails ssl validation without a certificate via HTTPS unless skipped" do
          Cli.run("target #{ENV["UAA_CLIENT_TARGET"]}")
          Cli.output.string.should include "Invalid SSL Cert"
        end

        it "skips ssl validation with a flag" do
          Cli.run("target #{ENV["UAA_CLIENT_TARGET"]} --skip-ssl-validation")
          Cli.output.string.should_not include "Invalid SSL Cert"
        end
      end

      describe 'targetting a https URL' do
        it "fails ssl validation without a certificate via HTTPS" do
          Cli.run("target #{ENV["UAA_CLIENT_TARGET"]}")
          Cli.output.string.should include "Invalid SSL Cert"
        end

        it "passes ssl validation if a valid rootCA is passed with an option" do
          Cli.run("target #{ENV["UAA_CLIENT_TARGET"]} --ca-cert #{ENV["UAA_CLIENT_CA_CERT_PATH"]}")
          Cli.output.string.should include "Target: #{ENV["UAA_CLIENT_TARGET"]}"
          Cli.output.string.should_not match /invalid/i
        end
      end

      describe 'targeting a URL without specifying the scheme' do
        it "uses HTTPS if --skip-ssl-validation is true" do
          Cli.run("target #{@url.host}:#{@url.port}/#{@url.path} --skip-ssl-validation")
          Cli.output.string.should include "https"
          Cli.output.string.should_not include "Invalid SSL Cert"
        end

        it "uses HTTPS if --ca-cert is true" do
          Cli.run("target #{@url.host}:#{@url.port}/#{@url.path} --ca-cert #{ENV["UAA_CLIENT_CA_CERT_PATH"]}")
          Cli.output.string.should include "https"
          Cli.output.string.should_not match /invalid/i
        end
      end

      describe 'using other commands after skipping ssl validation' do
        it "does not raise SSLException for the same target" do
          Cli.run("target #{ENV["UAA_CLIENT_TARGET"]} --skip-ssl-validation")
          Cli.run("token client get foo -s bar")
          Cli.output.string.should_not match /invalid/i
          Cli.run("groups")
          Cli.output.string.should_not match /invalid/i
        end
      end

      describe 'using other commands after setting ca-cert' do
        it "does not raise SSLException for the same target" do
          Cli.run("target #{ENV["UAA_CLIENT_TARGET"]} --ca-cert #{ENV["UAA_CLIENT_CA_CERT_PATH"]}")
          Cli.run("token client get foo -s bar")
          Cli.output.string.should_not match /invalid/i
          Cli.run("groups")
          Cli.output.string.should_not match /invalid/i
        end
      end
    end

  end
end
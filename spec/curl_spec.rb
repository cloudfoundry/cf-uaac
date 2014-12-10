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
  describe CurlCli do
    include SpecHelper

    before :all do
      Cli.configure("", nil, StringIO.new, true)
      setup_target(authorities: "clients.read,scim.read,scim.write")
      Cli.run("token client get #{@test_client} -s #{@test_secret}").should be
      Config.yaml.should include("access_token")
    end

    after :all do
      cleanup_target
    end

    it "prints usage when the path argument is not specified" do
      Cli.run("curl")

      Cli.output.string.should include "curl [path]"
      Cli.output.string.should include "-X | --request <method>"
      Cli.output.string.should include "-d | --data <data>"
    end

    it "hits the URL on the UAA target" do
      pending "Test not applicable in integration test runs" if ENV["UAA_CLIENT_TARGET"]

      Cli.run("curl /my-fake-endpoint")

      Cli.output.string.should include "GET #{@target}/my-fake-endpoint"
      Cli.output.string.should_not include "REQUEST BODY"
      Cli.output.string.should_not include "REQUEST HEADERS"
      Cli.output.string.should include "200 OK"
      Cli.output.string.should include "RESPONSE BODY:"
      Cli.output.string.should include "some fake response text"
    end

    it "displays the correct response text when we include a body in the request" do
      pending "Test not applicable in integration test runs" if ENV["UAA_CLIENT_TARGET"]

      Cli.run("curl -X PUT -d '{\"fake\": true}' -H 'Accept: application/json' /another-fake-endpoint")

      Cli.output.string.should include "PUT #{@target}/another-fake-endpoint"
      Cli.output.string.should include "REQUEST BODY: \"{\"fake\": true}\""
      Cli.output.string.should include "Accept: application/json"
      Cli.output.string.should include "202 ACCEPTED"
      Cli.output.string.should include "RESPONSE BODY:"
      Cli.output.string.should include "\"fake\": true"
      Cli.output.string.should include "\"updated\": 42"
    end

    it "handles 204 No Content response when Content-Type is missing" do
      pending "Test not applicable in integration test runs" if ENV["UAA_CLIENT_TARGET"]
      Cli.run("curl -X PUT /fake-endpoint-empty-response")

      Cli.output.string.should include "PUT #{@target}/fake-endpoint-empty-response"
      Cli.output.string.should include "204 NO CONTENT"
      Cli.output.string.should include "RESPONSE BODY:"
      Cli.output.string.should_not include "error"
    end

    it "uses headers passed from the command line" do
      pending "Test not applicable in integration test runs" if ENV["UAA_CLIENT_TARGET"]

      Cli.run("curl -H \"X-Something: non-standard header\" -H \"X-Another: something\" /my-fake-endpoint")

      Cli.output.string.should include "GET #{@target}/my-fake-endpoint"
      Cli.output.string.should include "REQUEST HEADERS:"
      Cli.output.string.should include "  X-Something: non-standard header"
      Cli.output.string.should include "  X-Another: something"
      Cli.output.string.should include "RESPONSE HEADERS:"
      Cli.output.string.should include "  Content-Type: text/plain"
    end

    it "hits an external server when a request host is specified in the command" do
      Cli.run("curl http://example.com/something")

      Cli.output.string.should include "GET http://example.com/something"
      Cli.output.string.should include "404 Not Found"
    end

    it "prints non-JSON responses" do
      Cli.run("curl http://example.com/something")

      Cli.output.string.should_not include "JSON::ParserError"
    end

    it "makes insecure requests with the -k flag" do
      Cli.run("curl https://example.com/ -k")

      Cli.output.string.should_not include "ECONNRESET"
      Cli.output.string.should include "200 OK"
    end
  end
end

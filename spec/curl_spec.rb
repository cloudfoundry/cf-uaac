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
      Cli.run("curl /my-fake-endpoint")

      Cli.output.string.should include "GET #{@target}/my-fake-endpoint"
      Cli.output.string.should_not include "REQUEST BODY"
      Cli.output.string.should include "200 OK"
      Cli.output.string.should include "RESPONSE BODY:"
      Cli.output.string.should include "\"body\": \"some fake response text\""
    end

    it "displays the correct response text when we include a body in the request" do
      Cli.run("curl -X PUT -d '{\"fake\": true}' /another-fake-endpoint")

      Cli.output.string.should include "PUT #{@target}/another-fake-endpoint"
      Cli.output.string.should include "REQUEST BODY: \"{\"fake\": true}\""
      Cli.output.string.should include "202 ACCEPTED"
      Cli.output.string.should include "RESPONSE BODY:"
      Cli.output.string.should include "\"fake\": true"
    end
  end
end

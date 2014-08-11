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
require 'net/http'
require 'em-http'
require 'uaa/http'
require 'cli/version'
require 'stub/server'

module CF::UAA

class StubHttp < Stub::Base
  route(:get, '/') { reply_in_kind "welcome to stub http, version #{CLI_VERSION}" }
  route( :get, '/bad') { reply.headers[:location] = ":;+)(\/"; reply_in_kind(3, "bad http status code") }
end

class HttpClient
  include Http
  def get(target, path = nil, headers = {}) http_get(target, path, headers) end
end

describe Http do

  include SpecHelper

  before :all do
    #Util.default_logger(:trace)
    @stub_http = Stub::Server.new(StubHttp, logger: Util.default_logger).run_on_thread
  end

  after :all do @stub_http.stop if @stub_http end

  it "gets something from stub server on a fiber" do
    frequest(true) {
      f = Fiber.current
      http = EM::HttpRequest.new("#{@stub_http.url}/").get
      http.errback { f.resume "error" }
      http.callback {
        http.response_header.http_status.should == 200
        f.resume http.response
      }
      Fiber.yield
    }.should match /welcome to stub http/
  end

  it "uses persistent connections from stubserver" do
    frequest(true) {
      f = Fiber.current
      conn = EM::HttpRequest.new("#{@stub_http.url}/")
      req1 = conn.get keepalive: true
      req1.errback { f.resume "error1" }
      req1.callback {
        req2 = conn.get
        req2.errback { f.resume req2.error }
        req2.callback { f.resume req2.response }
      }
      Fiber.yield
    }.should match /welcome to stub http/
  end

  it "gets something from stub server on a thread" do
    @async = false
    resp = Net::HTTP.get(URI("#{@stub_http.url}/"))
    resp.should match /welcome to stub http/
  end

  shared_examples_for "http client" do

    # the following is intended to test that a failed dns lookup will fail the
    # same way on the buggy em-http-request 1.0.0.beta3 client as it does on
    # the rest-client. However, some networks (such as the one I am on now)
    # configure the dhcp client with a dns server that will resolve
    # every name as a valid address, e.g. bad.example.bad returns an address
    # to a service signup screen. I have tried stubbing the code in various
    # ways:
     # EventMachine.stub(:connect) { raise EventMachine::ConnectionError, "fake error for bad dns lookup" }
     # EventMachine.unstub(:connect)
     # Socket.stub(:gethostbyname) { raise SocketError, "getaddrinfo: Name or service not known" }
     # Socket.unstub(:gethostbyname)
    # This has had varied success but seems rather brittle. Currently I have opted
    # to just make the domain name invalid with tildes, but this may not test
    # the desired code paths
    it "fails cleanly for a failed dns lookup" do
      result = frequest(@on_fiber) { @client.get("http://bad~host~name/") }
      result.should be_an_instance_of BadTarget
    end

    it "fails cleanly for a get operation, no connection to address" do
      result = frequest(@on_fiber) { @client.get("http://127.0.0.1:30000/") }
      result.should be_an_instance_of BadTarget
    end

    it "fails cleanly for a get operation with bad response" do
      frequest(@on_fiber) { @client.get(@stub_http.url, "/bad") }.should be_an_instance_of HTTPException
    end

    it "works for a get operation to a valid address" do
      status, body, headers = frequest(@on_fiber) { @client.get(@stub_http.url, "/") }
      status.should == 200
      body.should match /welcome to stub http/
    end

    it "should send debug information to a custom logger" do
      class CustomLogger
        attr_reader :log
        def initialize; @log = "" end
        def debug(str = nil) ; @log << (str ? str : yield) end
      end
      @client.logger = clog = CustomLogger.new
      clog.log.should be_empty
      frequest(@on_fiber) { @client.get(@stub_http.url, "/") }
      clog.log.should_not be_empty
    end
  end

  context "on a fiber" do
    before :all do
      @on_fiber = true
      @client = HttpClient.new
      @client.set_request_handler do |url, method, body, headers|
        f = Fiber.current
        connection = EventMachine::HttpRequest.new(url, connect_timeout: 2, inactivity_timeout: 2)
        client = connection.setup_request(method, head: headers, body: body)

        # This check is for proper error handling with em-http-request 1.0.0.beta.3
        if defined?(EventMachine::FailedConnection) && connection.is_a?(EventMachine::FailedConnection)
          raise BadTarget, "HTTP connection setup error: #{client.error}"
        end

        client.callback { f.resume [client.response_header.http_status, client.response, client.response_header] }
        client.errback { f.resume [:error, client.error] }
        result = Fiber.yield
        if result[0] == :error
          raise BadTarget, "connection failed" unless result[1] && result[1] != ""
          raise BadTarget, "connection refused" if result[1].to_s =~ /ECONNREFUSED/
          raise BadTarget, "unable to resolve address" if /unable.*server.*address/.match result[1]
          raise HTTPException, result[1]
        end
        [result[0], result[1], Util.hash_keys!(result[2], :dash)]
      end
    end
    it_should_behave_like "http client"
  end

  context "on a thread" do
    before :all do
      @on_fiber = false
      @client = HttpClient.new
    end
    it_should_behave_like "http client"
  end

end

end

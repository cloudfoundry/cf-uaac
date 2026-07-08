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
require 'uaa/http'
require 'uaa/cli/version'
require 'uaa/stub/server'

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

  it "gets something from stub server on a thread" do
    @async = false
    resp = Net::HTTP.get(URI("#{@stub_http.url}/"))
    resp.should match /welcome to stub http/
  end

  it "reuses connections to the same host (connection caching)" do
    # Replaces the old EM keepalive test. The Http module caches one HTTPClient
    # instance per host via @http_cache; verify multiple sequential requests
    # all succeed through that cache.
    client = HttpClient.new
    3.times do
      status, body, _ = client.get(@stub_http.url, "/")
      status.should == 200
      body.should match /welcome to stub http/
    end
  end

  it "works when called from a Ruby Fiber" do
    # Replaces the old EM-fiber GET test. The HTTP client is synchronous, so
    # calling it from a native Fiber must work without deadlocking.
    result = nil
    Fiber.new {
      result = begin
        status, body, _ = HttpClient.new.get(@stub_http.url, "/")
        [status, body]
      rescue => e
        e
      end
    }.resume
    result[0].should == 200
    result[1].should match /welcome to stub http/
  end

  shared_examples_for "http client" do

    # the following is intended to test that a failed dns lookup will fail
    # cleanly. Some networks resolve every name, so tildes are used to ensure
    # an invalid hostname.
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

  context "on a thread" do
    before :all do
      @on_fiber = false
      @client = HttpClient.new
    end
    it_should_behave_like "http client"
  end

  # Replaces the old "on a fiber" context which ran the shared examples through
  # an EventMachine async request handler via set_request_handler.
  # Now exercises set_request_handler with a simple Net::HTTP backend,
  # ensuring the callback interface itself works correctly.
  context "with a custom request handler (Net::HTTP backend)" do
    before :all do
      @on_fiber = false
      @client = HttpClient.new
      @client.set_request_handler do |url, method, body, headers|
        uri = URI.parse(url)
        http = Net::HTTP.new(uri.host, uri.port)
        request = Net::HTTP::Get.new(uri.request_uri, headers)
        begin
          resp = http.request(request)
          content_type = resp['content-type'] || ''
          [resp.code.to_i, resp.body, {'content-type' => content_type}]
        rescue SocketError, Errno::ECONNREFUSED, Errno::ECONNRESET => e
          raise CF::UAA::BadTarget, e.message
        rescue => e
          raise CF::UAA::HTTPException, e.message
        end
      end
    end
    it_should_behave_like "http client"
  end

end

end

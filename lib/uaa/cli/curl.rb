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

require 'uaa/cli/common'
require 'rack'
require 'net/http'
require 'uaa/http'
require 'json'

module CF::UAA
  class CurlCli < CommonCli
    include Http

    topic "CURL"

    define_option :request, "-X", "--request <method>", "request method type, defaults to GET"
    define_option :data, "-d", "--data <data>", "data included in request body"
    define_option :header, "-H", "--header <header>", "header to be included in the request"
    define_option :insecure, "-k", "--insecure", "makes request without verifying SSL certificates"
    define_option :bodyonly, "-b", "--bodyonly", "show body only in response"

    desc "curl [path]", "CURL to a UAA endpoint", :request, :data, :header, :insecure , :bodyonly do |path|
      return say_command_help(["curl"]) unless path

      uri = parse_uri(path)
      opts[:request] ||= "GET"
      print_request(opts[:request], uri, opts[:data], opts[:header], opts[:bodyonly])
      response = make_request(uri, opts)
      print_response(response, opts[:bodyonly])
    end

    def parse_uri(path)
      uri = URI.parse(path)
      unless uri.host
        uri = URI.parse("#{Config.target}#{path}")
      end
      uri
    end

    def print_request(request, uri, data, header, bodyonly)
      say_it("#{request} #{uri.to_s}", bodyonly)
      say_it("REQUEST BODY: \"#{data}\"", bodyonly) if data
      if header
        say_it("REQUEST HEADERS:", bodyonly)
        Array(header).each do |h|
          say_it("  #{h}", bodyonly)
        end
      end
      say_it("", bodyonly)
    end

    def make_request(uri, options)
      http = Net::HTTP.new(uri.host, uri.port)
      if uri.scheme == "https"
        http.use_ssl = true
        if options[:insecure]
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE
        end
      end
      request_class = Net::HTTP.const_get("#{options[:request][0]}#{options[:request][1..-1].downcase}")
      req = request_class.new(uri.request_uri)
      req["Authorization"] = "Bearer #{Config.value(:access_token)}"
      Array(options[:header]).each do |h|
        key, value = h.split(":")
        req[key] = value
      end
      http.request(req, options[:data])
    end

    def print_response(response, bodyonly)
      say_it("#{response.code} #{response.message}", bodyonly)
      say_it("RESPONSE HEADERS:", bodyonly)
      response.each_capitalized do |key, value|
        say_it("  #{key}: #{value}", bodyonly)
      end

      say_it("RESPONSE BODY:", bodyonly)
      if !response['Content-Type'].nil? && response['Content-Type'].include?('application/json')
        parsed = JSON.parse(response.body)
        formatted = JSON.pretty_generate(parsed)
        say(formatted)
      else
        say(response.body)
      end
    end

    def say_it(text, bodyonly)
      if !bodyonly
        say text
      end
    end
  end
end

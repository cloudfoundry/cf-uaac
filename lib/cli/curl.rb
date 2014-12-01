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

require 'cli/common'
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

    desc "curl [path]", "CURL to a UAA endpoint", :request, :data, :header, :insecure do |path|
      return say_command_help(["curl"]) unless path

      uri = parse_uri(path)
      opts[:request] ||= "GET"
      print_request(opts[:request], uri, opts[:data], opts[:header])
      response = make_request(uri, opts)
      print_response(response)
    end

    def parse_uri(path)
      uri = URI.parse(path)
      unless uri.host
        uri = URI.parse("#{Config.target}#{path}")
      end
      uri
    end

    def print_request(request, uri, data, header)
      say "#{request} #{uri.to_s}"
      say "REQUEST BODY: \"#{data}\"" if data
      if header
        say "REQUEST HEADERS:"
        Array(header).each do |h|
          say "  #{h}"
        end
      end
      say ""
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

    def print_response(response)
      say "#{response.code} #{response.message}"
      say "RESPONSE HEADERS:"
      response.each_capitalized do |key, value|
        say "  #{key}: #{value}"
      end

      say "RESPONSE BODY:"
      if !response['Content-Type'].nil? && response['Content-Type'].include?('application/json')
        parsed = JSON.parse(response.body)
        formatted = JSON.pretty_generate(parsed)
        say formatted
      else
        say response.body
      end
    end
  end
end

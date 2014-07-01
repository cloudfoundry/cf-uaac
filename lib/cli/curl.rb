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

    desc "curl [path]", "CURL to a UAA endpoint", :request, :data, :header do |path|
      return say_command_help(["curl"]) unless path

      uri = parse_uri(path)
      opts[:request] ||= "GET"
      print_request(opts[:request], uri, opts[:data], opts[:header])
      response = make_request(uri, opts[:request], opts[:data], opts[:header])
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

    def make_request(uri, request, data, header)
      http = Net::HTTP.new(uri.host, uri.port)
      request_class = Net::HTTP.const_get("#{request[0]}#{request[1..-1].downcase}")
      req = request_class.new(uri.request_uri)
      req["Authorization"] = "Bearer #{Config.value(:access_token)}"
      Array(header).each do |h|
        key, value = h.split(":")
        req[key] = value
      end
      http.request(req, data)
    end

    def print_response(response)
      say "#{response.code} #{response.message}"
      say "RESPONSE HEADERS:"
      response.each_capitalized do |key, value|
        say "  #{key}: #{value}"
      end

      say "RESPONSE BODY:"
      if response['Content-Type'].include?('application/json')
        parsed = JSON.parse(response.body)
        formatted = JSON.pretty_generate(parsed)
        say formatted
      else
        say response.body
      end
    end
  end
end

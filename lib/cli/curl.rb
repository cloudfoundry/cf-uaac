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
    desc "curl [path]", "CURL to a UAA endpoint", :request, :data do |path|
      return say_command_help(["curl"]) unless path

      url = "#{Config.target}#{path}"
      opts[:request] ||= "GET"

      say "#{opts[:request]} #{url}"
      say "REQUEST BODY: \"#{opts[:data]}\"" if opts[:data]
      say ""

      uri = URI.parse(url)
      http = Net::HTTP.new(uri.host, uri.port)
      request_class = Net::HTTP.const_get("#{opts[:request][0]}#{opts[:request][1..-1].downcase}")
      req = request_class.new(uri.request_uri)
      req["Authorization"] = "Bearer #{Config.value(:access_token)}"
      req["Accept"] = "application/json"
      response = http.request(req, opts[:data])

      say "#{response.code} #{response.message}"

      parsed = JSON.parse(response.body)
      formatted = JSON.pretty_generate(parsed)

      say "RESPONSE BODY:\n#{formatted}"
    end
  end
end

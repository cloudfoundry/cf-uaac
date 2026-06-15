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

require 'socket'
require 'date'
require 'logger'
require 'pp'
require 'erb'
require 'json'
require 'rack'

module Stub

class StubError < RuntimeError; end
class BadHeader < StubError; end

#------------------------------------------------------------------------------
class Request

  attr_reader :headers, :body, :path, :method
  def initialize; @state, @prelude = :init, "" end

  private

  def bslice(str, range)
    str.respond_to?(:byteslice) ? str.byteslice(range) : str.slice(range)
  end

  def add_lines(str)
    return @body << str if @state == :body
    processed = 0
    str.each_line("\r\n") do |ln|
      processed += ln.bytesize
      unless ln.chomp!("\r\n")
        raise BadHeader unless ln.ascii_only?
        return @prelude = ln # must be partial header at end of str
      end
      if @state == :init
        start = ln.split(/\s+/)
        @method, @path, @headers, @body = start[0].downcase, start[1], {}, ""
        raise BadHeader unless @method.ascii_only? && @path.ascii_only?
        @state = :headers
      elsif ln.empty?
        @state, @content_length = :body, headers["content-length"].to_i
        return @body << bslice(str, processed..-1)
      else
        raise BadHeader unless ln.ascii_only?
        key, sep, val = ln.partition(/:\s+/)
        @headers[key.downcase] = val
      end
    end
  end

  public

  # adds data to the request, returns truthy if request is complete
  def completed?(str)
    str, @prelude = @prelude + str, "" unless @prelude.empty?
    add_lines(str)
    return unless @state == :body && @body.bytesize >= @content_length
    @prelude = bslice(@body, @content_length..-1)
    @body = bslice(@body, 0..@content_length)
    @state = :init
  end

  def cookies
    return {} unless chdr = @headers["cookie"]
    chdr.strip.split(/\s*;\s*/).each_with_object({}) do |pair, o|
      k, v = pair.split(/\s*=\s*/)
      o[k.downcase] = v
    end
  end

end

#------------------------------------------------------------------------------
class Reply
  attr_accessor :status, :headers, :body
  def initialize(status = 200) @status, @headers, @cookies, @body = status, {}, [], "" end
  def to_s
    message = Rack::Utils::HTTP_STATUS_CODES[@status]
    reply = "HTTP/1.1 #{@status} #{message.upcase if message}\r\n"
    headers["server"], headers["date"] = "stub server", DateTime.now.httpdate
    headers["content-length"] = body.bytesize
    headers.each { |k, v| reply << "#{k}: #{v}\r\n" }
    @cookies.each { |c| reply << "Set-Cookie: #{c}\r\n" }
    reply << "\r\n" << body
  end
  def json(status = nil, info)
    info = {message: info} unless info.respond_to? :each
    @status = status if status
    headers["content-type"] = "application/json"
    @body = JSON.dump(info)
    nil
  end
  def text(status = nil, info)
    @status = status if status
    headers["content-type"] = "text/plain"
    @body = info.pretty_inspect
    nil
  end
  def html(status = nil, info)
    @status = status if status
    headers["content-type"] = "text/html"
    info = ERB::Util.html_escape(info.pretty_inspect) unless info.is_a?(String)
    @body = "<html><body>#{info}</body></html>"
    nil
  end
  def empty()
    @status = 204
    @body = ''
    nil
  end
  def set_cookie(name, value, options = {})
    @cookies << options.each_with_object("#{name}=#{value}") { |(k, v), o|
      o << (v.nil? ? "; #{k}" : "; #{k}=#{v}")
    }
  end
end

#------------------------------------------------------------------------------
# request handler logic -- server is initialized with a class derived from this.
# there will be one instance of this object per connection.
class Base
  attr_accessor :request, :reply, :match, :server

  def self.route(http_methods, matcher, filters = {}, &handler)
    matcher = Regexp.new("^#{Regexp.escape(matcher.to_s)}$") unless matcher.is_a?(Regexp)
    filters = filters.each_with_object({}) { |(k, v), o|
      o[k.downcase] = v.is_a?(Regexp) ? v : Regexp.new("^#{Regexp.escape(v.to_s)}$")
    }
    @routes ||= {}
    @route_number = @route_number.to_i + 1
    route_name = "route_#{@route_number}".to_sym
    define_method(route_name, handler)
    [*http_methods].each do |m|
      m = m.to_s.downcase
      @routes[m] ||= []
      i = @routes[m].index { |r| r[0].to_s.length < matcher.to_s.length }
      unless i && @routes[m][i][0] == matcher
        @routes[m].insert(i || -1, [matcher, filters, route_name])
      end
    end
  end

  def self.find_route(request)
    if @routes && (rary = @routes[request.method])
      rary.each { |r; m|
        next unless (m = r[0].match(request.path))
        r[1].each { |k, v|
          next if v.match(request.headers[k])
          return reply_in_kind(400,  "header '#{k}: #{request.headers[k]}' is not accepted")
        }
        return [m, r[2]]
      }
    end
    [nil, :default_route]
  end

  def initialize(server)
    @server, @request, @reply, @match = server, Request.new, Reply.new, nil
  end

  def default_route; reply_in_kind(404, error: "path not handled") end

  def process
    @reply = Reply.new
    if server.root
      return default_route unless request.path.start_with?(server.root)
      request.path.slice!(0..server.root.length - 1)
    end
    @match, handler = self.class.find_route(request)
    server.logger.debug "processing #{request.method} to path #{request.path}"
    send handler
    reply.headers['connection'] ||= request.headers['connection'] if request.headers['connection']
    server.logger.debug "replying to path #{request.path} with #{reply.body.length} bytes of #{reply.headers['content-type']}"
    #server.logger.debug "full reply is: #{reply.body.inspect}"
  rescue Exception => e
    server.logger.debug "exception processing request: #{e.message}"
    server.trace { e.backtrace }
    reply_in_kind 500, e
  end

  def reply_in_kind(status = nil, info)
    case request.headers['accept']
    when /application\/json/ then reply.json(status, info)
    when /text\/html/ then reply.html(status, info)
    else reply.text(status, info)
    end
  end

end

#------------------------------------------------------------------------------
class Server

  private

  # Handle one TCP client socket: parse requests, dispatch, write replies.
  # Supports keep-alive: the Request object resets itself after each
  # completed? call, so the same req_handler is reused for pipelined requests.
  def handle_client(socket)
    req_handler = @req_handler.new(self)
    loop do
      # If leftover bytes from the previous request already complete the next
      # one (pipelining / chunked reads), process without a blocking read.
      unless req_handler.request.completed?("")
        begin
          data = socket.readpartial(4096)
        rescue EOFError, Errno::ECONNRESET
          break
        end
        next unless req_handler.request.completed?(data)
      end
      req_handler.process
      socket.write(req_handler.reply.to_s)
      break if req_handler.reply.headers['connection'] =~ /^close$/i || @status != :running
    end
  rescue Errno::ECONNRESET, Errno::EPIPE, IOError => e
    logger.debug "connection error: #{e.message}"
  ensure
    socket.close rescue nil
    @mutex.synchronize { @connections.delete(socket) }
    logger.debug "connection closed"
  end

  # Accept connections in a loop until the server is stopped or the listening
  # socket is closed.
  def accept_loop
    loop do
      begin
        socket = @tcp_server.accept_nonblock
        @mutex.synchronize { @connections << socket }
        logger.debug "starting connection"
        Thread.new(socket) { |s| handle_client(s) }
      rescue IO::WaitReadable, Errno::EINTR
        IO.select([@tcp_server], nil, nil, 0.5) rescue nil
        break if @status != :running
      rescue Errno::EBADF, IOError
        break
      end
    end
  rescue => e
    logger.debug "accept loop error: #{e.message}" unless e.is_a?(IOError) || e.is_a?(Errno::EBADF)
  ensure
    @status = :stopped
    logger.debug "server really done"
  end

  public

  attr_reader :host, :port, :status, :logger, :root
  attr_accessor :info
  def url; "http://#{@host}:#{@port}" end
  def trace(msg = nil, &blk); logger.trace(msg, &blk) if logger.respond_to?(:trace) end

  def initialize(req_handler, options)
    @req_handler = req_handler
    @logger = options[:logger] || Logger.new($stdout)
    @info = options[:info]
    @host = options[:host] || "localhost"
    @init_port = options[:port] || 0
    @root = options[:root]
    @connections = []
    @mutex = Mutex.new
    @status = :stopped
    @server_thread = nil
  end

  def start
    raise ArgumentError, "attempt to start a server that's already running" unless @status == :stopped
    logger.debug "starting #{self.class} server #{@host}"
    @tcp_server = TCPServer.new(@host, @init_port)
    @port = @tcp_server.addr[1]
    logger.info "#{self.class} server started at #{url}"
    @status = :running
    self
  end

  # Start the server and run the accept loop on a background thread.
  # Returns immediately; caller can use #url and #port right away.
  def run_on_thread
    raise ArgumentError, "can't run on thread, server already running" if @status == :running
    logger.debug "starting server on thread"
    start
    @server_thread = Thread.new { accept_loop }
    logger.debug "running on thread"
    self
  end

  # Start the server and run the accept loop on the calling thread (blocking).
  def run
    raise ArgumentError, "can't run, server already running" if @status == :running
    @server_thread = Thread.current
    start
    accept_loop
    logger.debug "server and event loop done"
  end

  # Stop accepting new connections, close the listening socket, and wait for
  # the accept loop thread to mark status :stopped.
  def stop
    logger.debug "stopping server"
    @status = :stopping
    @tcp_server.close rescue nil
    sleep 0.05 while @status != :stopped
  end

  def delete_connection(conn)
    logger.debug "deleting connection"
    @mutex.synchronize { @connections.delete(conn) }
  end

end

end

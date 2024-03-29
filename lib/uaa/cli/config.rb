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

require 'yaml'
require 'uaa/util'

module CF::UAA

class Config

  class << self; attr_reader :target, :context end

  def self.config; @config ? @config.dup : {} end
  def self.loaded?; !!@config end
  def self.yaml; YAML.dump(Util.hash_keys(@config, :str)) end
  def self.target?(tgt) tgt if @config[tgt = subhash_key(@config, tgt)] end

  # if a yaml string is provided, config is loaded from the string, otherwise
  # config is assumed to be a file name to read and store config.
  # config can be retrieved in yaml form from Config.yaml
  def self.load(config = nil)
    @config = {}
    return unless config
    if config =~ /^---/ || config == ""
      @config = config == "" ? {} : YAML.load(config)
      @config_file = nil
    elsif File.exist?(@config_file = config)
      if (@config = YAML.load_file(@config_file)) && @config.is_a?(Hash)
        @config.each { |k, v| break @config = nil if k.to_s =~ / / }
      end
      unless @config && @config.is_a?(Hash)
          STDERR.puts "", "Invalid config file #{@config_file}.",
            "If it's from an old version of uaac, please remove it.",
            "Note that the uaac command structure has changed.",
            "Please review the new commands with 'uaac help'", ""
          exit 1
      end
    else # file doesn't exist, make sure we can write it now
      self.write_file(@config_file, "--- {}\n\n")
    end
    Util.hash_keys!(@config, :sym)
    @context = current_subhash(@config[@target][:contexts]) if @target = current_subhash(@config)
  end

  def self.save
    self.write_file(@config_file, YAML.dump(Util.hash_keys(@config, :str))) if @config_file
    true
  end

  def self.target=(tgt)
    unless t = set_current_subhash(@config, tgt, @target)
      raise ArgumentError, "invalid target, #{tgt}"
    end
    @context = current_subhash(@config[t][:contexts])
    save
    @target = t
  end

  def self.target_opts(hash)
    raise ArgumentError, "target not set" unless @target
    return unless hash and !hash.empty?
    raise ArgumentError, "'contexts' is a reserved key" if hash.key?(:contexts)
    @config[@target].merge! Util.hash_keys(hash, :sym)
    save
  end

  def self.target_value(attr)
    raise ArgumentError, "target not set" unless @target
    @config[@target][attr]
  end

  def self.context=(ctx)
    raise ArgumentError, "target not set" unless @target
    unless c = set_current_subhash(@config[@target][:contexts] ||= {}, ctx, @context)
      raise ArgumentError, "invalid context, #{ctx}"
    end
    save
    @context = c
  end

  def self.valid_context(ctx)
    raise ArgumentError, "target not set" unless @target
    k = existing_key(@config[@target][:contexts] ||= {}, ctx)
    raise ArgumentError, "unknown context #{ctx}" unless k
    k
  end

  def self.delete(tgt = nil, ctx = nil)
    if tgt && ctx
      unless @config[tgt][:contexts].nil?
        ctx = ctx.downcase.to_sym
        @config[tgt][:contexts].delete(ctx)
      end
      @context = nil if tgt == @target && ctx == @context
    elsif tgt
      @config.delete(tgt)
      @target = @context = nil if tgt == @target
    else
      @target, @context, @config = nil, nil, {}
    end
    save
  end

  def self.add_opts(hash)
    raise ArgumentError, "target and context not set" unless @target && @context
    return unless hash and !hash.empty?
    @config[@target][:contexts][@context].merge! Util.hash_keys(hash, :sym)
    save
  end

  def self.value(attr)
    raise ArgumentError, "target and context not set" unless @target && @context
    @config[@target][:contexts][@context][attr]
  end

  def self.[](attr) value(attr) end

  def self.delete_attr(attr)
    raise ArgumentError, "target and context not set" unless @target && @context
    @config[@target][:contexts][@context].delete(attr)
  end

  # these are all class methods and so can't really be private, but the
  # methods below here are not intended to be part of the public interface
  private

  def self.write_file(filename, content)
    File.open(filename, 'w') { |f| f.write content }
    File.chmod(0600, filename)
  end

  def self.current_subhash(hash)
    return unless hash
    key = nil
    hash.each { |k, v| key ? v.delete(:current) : (key = k if v[:current]) }
    key
  end

  # key can be an integer index of the desired subhash or the key symbol or string
  def self.subhash_key(hash, key)
    case key
    when Integer then hash.each_with_index { |(k, v), i| return k if i == key }; nil
    when String then key.downcase.to_sym
    when Symbol then key.to_s.downcase.to_sym
    else nil
    end
  end

  def self.existing_key(hash, key)
    k = subhash_key(hash, key)
    k if hash[k]
  end

  def self.set_current_subhash(hash, newcurrent, oldcurrent)
    return unless k = subhash_key(hash, newcurrent)
    hash[oldcurrent].delete(:current) if oldcurrent
    (hash[k] ||= {}).merge!(current: true)
    k
  end

end

end

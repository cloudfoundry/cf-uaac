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

require 'set'
require 'cli/common'
require 'uaa'

module CF::UAA

class GroupCli < CommonCli

  topic "Groups", "group"

  def gname(name) name || ask("Group name") end

  desc "groups [filter]", "List groups", :attrs, :start, :count do |filter|
    scim_common_list(:group, filter)
  end

  desc "group get [name]", "Get specific group information", :attrs do |name|
    pp scim_request { |sr| scim_get_object(sr, :group, gname(name), opts[:attrs]) }
  end

  desc "group add [name]", "Adds a group" do |name|
    pp scim_request { |scim| scim.add(:group, displayName: gname(name)) }
  end

  desc "group delete [name]", "Delete group" do |name|
    pp scim_request { |scim|
      scim.delete(:group, scim.id(:group, gname(name)))
      "success"
    }
  end

  define_option :start, "--start <start>", "show results starting at this index"
  define_option :count, "--count <count>", "number of results to show"
  desc "group mappings", "List all the mappings between uaa scopes and external groups", :start, :count do
    start, count = opts[:start], opts[:count]
    return gripe "Please enter a valid start index" if start unless is_integer?(start)
    return gripe "Please enter a valid count" if count unless is_natural_number?(count)

    response = scim_request { |scim| scim.list_group_mappings(start, count) }

    if response
      grouped_group_mappings = {}
      response["resources"].each do |resource|
        grouped_group_mappings[resource['origin']] ||= Array.new
        grouped_group_mappings[resource['origin']] << {resource['displayname'] => resource['externalgroup']}
      end
      response["resources"] = grouped_group_mappings
      pp response
    end
  end

  define_option :id, "--id <id>", "map uaa group using group id"
  define_option :name, "--name <name>", "map uaa scope using group name"
  define_option :origin, "--origin <origin>", "map uaa scope to external group for this origin. Defaults to ldap."
  desc "group map [external_group]", "Map uaa groups to external groups", :id, :name, :origin do |external_group|
    return gripe "Please provide a group name or id" unless opts[:id] || opts[:name]
    return gripe "Please provide an external group" unless external_group

    group = opts[:id] ? opts[:id] : opts[:name]
    is_id = opts[:id] ? true : false
    origin = opts[:origin] ? opts[:origin] : 'ldap'
    pp scim_request { |ua|
      response = ua.map_group(group, is_id, external_group, origin)
      raise BadResponse, "no  group id found in response of external group mapping" unless response["groupid"]
      "Successfully mapped #{response["displayname"]} to #{external_group} for origin #{origin}"
    }
  end

  desc "group unmap [group_name] [external_group]", "Unmaps an external group from a uaa group", :origin do |group_name, external_group|
    return gripe "Please provide a group name and external group" unless group_name && external_group

    origin = opts[:origin] ? opts[:origin] : 'ldap'

    response = Cli.run("group get #{group_name}")
    if response
      group_id = response['id']
    else
      return gripe "Group #{group_name} not found"
    end


    pp scim_request { |ua|
      ua.unmap_group(group_id, external_group, origin)
      "Successfully unmapped #{external_group} from #{group_name} for origin #{origin}"
    }
  end

  def id_set(objs)
    objs.each_with_object(Set.new) {|o, s|
      id = o.is_a?(String)? o: (o["id"] || o["value"] || o["memberid"])
      raise BadResponse, "no id found in response of current members" unless id
      s << id
    }
  end

  def update_members(scim, name, attr, users, add = true)
      group = scim_get_object(scim, :group, gname(name))
      old_ids = id_set(group[attr] || [])
      new_ids = id_set(scim.ids(:user, *users))
      if add
        raise "not all users found, none added" unless new_ids.size == users.size
        group[attr] = (old_ids + new_ids).to_a
        raise "no new users given" unless group[attr].size > old_ids.size
      else
        raise "not all users found, none deleted" unless new_ids.size == users.size
        group[attr] = (old_ids - new_ids).to_a
        raise "no existing users to delete" unless group[attr].size < old_ids.size
        group.delete(attr) if group[attr].empty?
      end
      scim.put(:group, group)
      "success"
  end

  desc "member add [name] [users...]", "add members to a group" do |name, *users|
    pp scim_request { |scim| update_members(scim, name, "members", users) }
  end

  desc "member delete [name] [users...]", "remove members from a group" do |name, *users|
    pp scim_request { |scim| update_members(scim, name, "members", users, false) }
  end

  desc "group reader add [name] [users...]", "add users who can read the members" do |name, *users|
    pp scim_request { |scim| update_members(scim, name, "readers", users) }
  end

  desc "group reader delete [name] [users...]", "delete users who can read members" do |name, *users|
    pp scim_request { |scim| update_members(scim, name, "readers", users, false) }
  end

  desc "group writer add [name] [users...]", "add users who can modify group" do |name, *users|
    pp scim_request { |scim| update_members(scim, name, "writers", users) }
  end

  desc "group writer delete [name] [users...]", "remove user who can modify group" do |name, *users|
    pp scim_request { |scim| update_members(scim, name, "writers", users, false) }
  end

  private

  def is_natural_number?(input)
    is_integer?(input) && input.to_i > -1
  end

  def is_integer?(input)
    input && (input.to_i.to_s == input)
  end
end

end


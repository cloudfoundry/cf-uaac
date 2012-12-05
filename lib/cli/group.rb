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

require 'set'
require 'cli/common'
require 'uaa'

module CF::UAA

class GroupCli < CommonCli

  topic "Groups", "group"

  def gname(name) name || ask("Group name") end

  desc "groups [filter]", "List groups", :attrs, :start, :count do |filter|
    pp scim_request { |ua|
      query = { attributes: opts[:attrs], filter: filter }
      opts[:start] || opts[:count] ?
        ua.query_groups(query.merge!(startIndex: opts[:start], count: opts[:count])):
        ua.all_pages(:group, query)
    }
  end

  desc "group get [name]", "Get specific group information" do |name|
    pp scim_request { |ua| ua.get(:group, ua.id(:group, gname(name))) }
  end

  desc "group add [name]", "Adds a group" do |name|
    pp scim_request { |ua| ua.add(:group, displayName: gname(name)) }
  end

  desc "group delete [name]", "Delete group" do |name|
    pp scim_request { |ua| 
      ua.delete(:delete, ua.id(:group, gname(name)))
      "success" 
    }
  end

  def id_set(objs)
    objs.each_with_object(Set.new) {|o, s| 
      s << (o.is_a?(String)? o: (o["id"] || o["value"]))
    }
  end

  desc "member add [name] [members...]", "add members to a group" do |name, *members|
    pp scim_request { |ua|
      group = ua.get(:group, ua.id(:group, gname(name)))
      old_ids = id_set(group["members"] || [])
      new_ids = id_set(ua.ids(:user, *members))
      raise "not all members found, none added" unless new_ids.size == members.size
      group["members"] = (old_ids + new_ids).to_a
      raise "no new members given" unless group["members"].size > old_ids.size
      ua.put(:group, group)
      "success"
    }
  end

  desc "member delete [name] [members...]", "remove members from a group" do |name, *members|
    pp scim_request { |ua|
      group = ua.get(:group, ua.id(:group, gname(name)))
      old_ids = id_set(group["members"] || [])
      new_ids = id_set(ua.ids(:user, *members))
      raise "not all members found, none deleted" unless new_ids.size == members.size
      group["members"] = (old_ids - new_ids).to_a
      raise "no existing members to delete" unless group["members"].size < old_ids.size
      group.delete("members") if group["members"].empty?
      ua.put(:group, group)
      "success"
    }
  end

end

end

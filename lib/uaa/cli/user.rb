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

module CF::UAA

class UserCli < CommonCli

  topic 'User Accounts', 'account'

  define_option :origin, '--origin <name>, select user to update by identity provider origin. Defaults to UAA'
  define_option :givenName, '--given_name <name>'
  define_option :familyName, '--family_name <name>'
  define_option :emails, '--emails <addresses>'
  define_option :phoneNumbers, '--phones <phone_numbers>'
  USER_INFO_OPTS = [:origin, :givenName, :familyName, :emails, :phoneNumbers]

  def user_opts(info = {})
    [:emails, :phoneNumbers].each do |o|
      next unless opts[o]
      info[o] = Util.arglist(opts[o]).each_with_object([]) { |v, a| a << {:value => v} }
    end
    n = [:givenName, :familyName].each_with_object({}) { |o, n| n[o] = opts[o] if opts[o] }
    info[:name] = n unless n.empty?
    info[:origin] = opts[:origin] if opts[:origin]
    info
  end

  define_option :attrs, '-a', '--attributes <names>', 'output for each user'
  define_option :start, '--start <number>', 'start of output page'
  define_option :count, '--count <number>', 'max number per page'
  desc 'users [filter]', 'List user accounts', :attrs, :start, :count do |filter|
    scim_common_list(:user, filter)
  end

  desc 'user get [name]', 'Get specific user account', :origin, :attrs do |name|
    pp scim_request { |sr| scim_get_user_object(sr, :user, username(name), opts[:origin], opts[:attrs]) }
  end

  desc 'user add [name]', 'Add a user account', *USER_INFO_OPTS, :password do |name|
    info = {userName: username(name), password: ((opts[:origin] == nil || opts[:origin] =='uaa') ? verified_pwd('Password', opts[:password]): nil)}
    pp scim_request { |ua|
      ua.add(:user, user_opts(info))
      'user account successfully added'
    }
  end

  define_option :del_attrs, '--del_attrs <attr_names>', 'list of attributes to delete'
  desc 'user update [name]', 'Update a user account with specified options',
      *USER_INFO_OPTS, :del_attrs do |name|
    return say 'no user updates specified' if (updates = user_opts).empty?
    pp scim_request { |ua|
      info = scim_get_user_object(ua, :user, username(name), opts[:origin])
      opts[:del_attrs].each { |a| info.delete(a.to_s) } if opts[:del_attrs]
      ua.put(:user, info.merge(updates))
      'user account successfully updated'
    }
  end

  desc 'user delete [name]', 'Delete user account', :origin do |name|
    pp scim_request { |ua|
      user = scim_get_user_object(ua, :user, username(name), opts[:origin])
      ua.delete(:user, user['id'])
      'user account successfully deleted'
    }
  end

  desc 'user ids [username|id...]', 'Gets user names and ids for the given users' do |*users|
    pp scim_request { |ua|
      users = Util.arglist(ask('names or ids of users')) if !users || users.empty?
      ids = ua.ids(:user_id, *users)
      raise NotFound, 'no users found' unless ids && ids.length > 0
      ids
    }
  end

  desc 'user unlock [name]', 'Unlocks the user account' do |name|
    pp scim_request { |ua|
      ua.unlock_user( ua.id(:user, username(name)))
      'user account successfully unlocked'
    }
  end

  desc 'user deactivate [name]', 'Deactivates user' do |name|
    pp scim_request { |ua|
      change_activation(ua, name, false)
      'user account successfully deactivated'
    }
  end

  desc 'user activate [name]', 'Activates user' do |name|
    pp scim_request { |ua|
      change_activation(ua, name, true)
      'user account successfully activated'
    }
  end

  desc 'password set [name]', 'Set password', :password do |name|
    pp scim_request { |ua|
      ua.change_password(ua.id(:user, username(name)), verified_pwd('New password', opts[:password]))
      'password successfully set'
    }
  end

  define_option :old_password, '-o', '--old_password <password>', 'current password'
  desc 'password change', 'Change password for authenticated user in current context', :old_password, :password do
    pp scim_request { |ua|
      raise 'no user_id in current context' unless Config.value(:user_id)
      oldpwd = opts[:old_password] || ask_pwd('Current password')
      ua.change_password(Config.value(:user_id), verified_pwd('New password', opts[:password]), oldpwd)
      'password successfully changed'
    }
  end

  def change_activation(ua, name, activate)
    info = ua.get(:user, ua.id(:user, username(name)))

    required_info = ['id', 'username', 'name', 'emails', 'meta'].inject({}) do |res, required_param|
      res[required_param] = info[required_param]
      res
    end

    required_info['active'] = activate
    ua.patch(:user, required_info)
  end
end

end

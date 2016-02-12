# CloudFoundry UAA Command Line Client

[![Build Status](https://travis-ci.org/cloudfoundry/cf-uaac.svg?branch=master)](https://travis-ci.org/cloudfoundry/cf-uaac)
[![Gem Version](https://badge.fury.io/rb/cf-uaac.png)](https://rubygems.org/gems/cf-uaac)

## Installation

From Rubygems:

`gem install cf-uaac`

Or to build and install the gem:

```
bundle install
gem build cf-uaac.gemspec
gem install cf-uaac*.gem
```


## Concepts

The user uses a client (like a webapp, or uaac) to do things. The client and the user have different secrets; both the user's and client's secret are passwords.


## Connecting and logging in

* `uaac help` opens up the help menu and shows a full list of commands.
* `uaac target` tells UAAC which UAA you're targeting. e.g. `uaa.example.io`.
* `uaac target <target-number>` lets you choose a registered target.
* `uaac targets` lists all registered targets.
* `uaac token client get (-s <your-client-secret>)` authenticates and gets your token so it can be used by UAAC. The `-s` or `--secret` flag is for inputting your secret, otherwise it will be asked for by UAAC.

Now that UAAC has your token, you're able to run commands and hit the endpoints that your client has the proper scopes for. A list of scopes can be found in [UAA's API documentation.](https://github.com/cloudfoundry/uaa/blob/master/docs/UAA-APIs.rst#scopes-authorized-by-the-uaa)

To use the APIs, see: https://github.com/cloudfoundry/cf-uaa-lib


## Creating clients

Authenticate as `admin`, or a user with the right permissions: `clients.admin` or `clients.write`.

`uaac client add -i` brings up the interactive interface. If entering multiple values, separate them with commas.

Scopes and authorities are different in the context of a client.

* Scopes is a list of permitted scopes for this client to obtain on behalf of a user.
* Authorities is a list of granted authorities for the client, such as `uaa.admin` or `scim.invite`.

`uaac contexts` will list the scopes for a client, which correspond to the users' authorities.


## Tests

Run the tests with rake:

`bundle exec rake test`

Run the tests and see a fancy coverage report:

`bundle exec rake cov`

Run integration tests (on a server running on localhost:8080/uaa):

```
export UAA_CLIENT_ID="admin"
export UAA_CLIENT_SECRET="adminsecret"
export UAA_CLIENT_TARGET="http://localhost:8080/uaa"
bundle exec rake test
```
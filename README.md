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

The user uses a client (like a webapp, or uaac) to do things. The client and the user have different secrets; the user's secret is a password, and the client's secret is a hex string.


## Run it

    $ uaac help
    $ uaac target uaa.cloudfoundry.com
    $ uaac token get <cf username> (-s <client secret>)
    $ uaac token decode

To use the APIs, see: https://github.com/cloudfoundry/cf-uaa-lib

## Tests

Run the tests with rake:

    $ bundle exec rake test

Run the tests and see a fancy coverage report:

    $ bundle exec rake cov

Run integration tests (on a server running on localhost:8080/uaa):

    $ export UAA_CLIENT_ID="admin"
    $ export UAA_CLIENT_SECRET="adminsecret"
    $ export UAA_CLIENT_TARGET="http://localhost:8080/uaa"
    $ bundle exec rake test

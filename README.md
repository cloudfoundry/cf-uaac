# CloudFoundry UAA Command Line Client

## Install from rubgems

    $ gem install cf-uaac

## Build and install from source

    $ bundle install
    $ gem build cf-uaac.gemspec
    $ gem install cf-uaac*.gem

## Run it

    $ uaac help
    $ uaac target uaa.cloudfoundry.com
    $ uaac token get <your-cf-username>
    $ uaac token decode

To use the APIs, see: https://github.com/cloudfoundry/cf-uaa-lib

## Tests

Run the tests with rake:

    $ bundle exec rake test

Run the tests and see a fancy coverage report:

    $ bundle exec rake cov

Run integration tests (with a server running on localhost:8080/uaa):

    $ export UAA_CLIENT_ID="admin"
    $ export UAA_CLIENT_SECRET="adminsecret"
    $ export UAA_CLIENT_TARGET="http://localhost:8080/uaa"
    $ bundle exec rake test

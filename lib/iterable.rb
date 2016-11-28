require "iterable/version"
require "iterable/client"

module Iterable
  class ClientError < StandardError
  end

  class UnavailableError < StandardError
  end

  # Provides a global place to configure the credentials for an application.
  # For instance, in your Rails app, create +config/initializers/sailthru.rb+
  # and place this line in it:
  #
  #     Sailthru.credentials('apikey', 'secret')
  #
  # Now you can create a client instance easily via Sailthru::Client.new
  #
  def self.credentials(api_key)
    @api_key = api_key
  end

  def self.api_key
    @api_key
  end
end

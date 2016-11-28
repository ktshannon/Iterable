$LOAD_PATH.unshift File.expand_path("../../lib", __FILE__)
require "iterable"
require 'vcr'
require 'webmock/rspec'
 
TEST_API_KEY = "d9623b8cf0d74b3380f0f2f0ee96eb0b"
TEST_EMAIL_ADDRESS = "kyle@bustedtees.com"
 
RSpec.configure do |config|
  # some (optional) config here
end
 
VCR.configure do |c|
  c.cassette_library_dir = "spec/fixtures/cassettes"
  c.hook_into :webmock
  c.default_cassette_options = { :record => :once }
end
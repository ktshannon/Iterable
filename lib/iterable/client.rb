require 'iterable/helpers'
require 'iterable/version'

require 'net/http'
require 'net/http/post/multipart'
require 'uri'
require 'cgi'
require 'json'

module Iterable
  class Client
    DEFAULT_API_URI = 'https://api.iterable.com'

    include Helpers

    attr_accessor :verify_ssl

    # params:
    #   api_key, String
    #   secret, String
    #   api_uri, String
    #
    # Instantiate a new client; constructor optionally takes overrides for key/secret/uri and proxy server settings.
    def initialize(api_key=nil, api_uri=nil, proxy_host=nil, proxy_port=nil, opts={})
      @api_key = api_key || Iterable.api_key || raise(ArgumentError, "You must provide an API key or call Iterable.credentials() first")
      @api_uri = api_uri.nil? ? DEFAULT_API_URI : api_uri
      @proxy_host = proxy_host
      @proxy_port = proxy_port
      @verify_ssl = true
      @opts = opts
      @last_rate_limit_info = {}
    end

    # params:
    #   template_name, String
    #   email, String
    #   vars, Hash
    #   options, Hash
    #     replyto: override Reply-To header
    #     test: send as test email (subject line will be marked, will not count towards stats)
    # returns:
    #   Hash, response data from server
    def send_email(template_name, email, vars={}, options = {}, schedule_time = nil, limit = {})
      post = {}
      post[:template] = template_name
      post[:email] = email
      post[:vars] = vars if vars.length >= 1
      post[:options] = options if options.length >= 1
      post[:schedule_time] = schedule_time if !schedule_time.nil?
      post[:limit] = limit if limit.length >= 1
      api_post(:send, post)
    end

    def get_lists
      api_get(:list, {})
    end

    protected

    # params:
    #   action, String
    #   data, Hash
    #   request, String "GET" or "POST"
    # returns:
    #   Hash
    #
    # Perform an API request, using the shared-secret auth hash.
    #
    def api_request(action, data, request_type, binary_key = nil)
      if !binary_key.nil?
        binary_key_data = data[binary_key]
        data.delete(binary_key)
      end

      if data[:format].nil? || data[:format] == 'json'
        data = prepare_json_payload(data)
      else
        data[:api_key] = @api_key
        data[:format] ||= 'json'
      end

      if !binary_key.nil?
        data[binary_key] = binary_key_data
      end
      _result = http_request(action, data, request_type, binary_key)

      # NOTE: don't do the unserialize here
      if data[:format] == 'json'
        begin
          unserialized = JSON.parse(_result)
          return unserialized ? unserialized : _result
        rescue JSON::JSONError => e
          return {'error' => e}
        end
      end
      _result
    end

    # set up our post request
    def set_up_post_request(uri, data, headers, binary_key = nil)
      if !binary_key.nil?
        binary_data = data[binary_key]

        if binary_data.is_a?(StringIO)
          data[binary_key] = UploadIO.new(
            binary_data, "text/plain", "local.path"
          )
        else
          data[binary_key] = UploadIO.new(
            File.open(binary_data), "text/plain"
          )
        end

        req = Net::HTTP::Post::Multipart.new(uri.path, data)
      else
        req = Net::HTTP::Post.new(uri.path, headers)
        req.set_form_data(data)
      end
      req
    end

    # params:
    #   uri, String
    #   data, Hash
    #   method, String "GET" or "POST"
    # returns:
    #   String, body of response
    def http_request(action, data, method = 'POST', binary_key = nil)
      data = flatten_nested_hash(data, false)

      uri = "#{@api_uri}/#{action}"
      if method != 'POST'
        uri += "?" + data.map{ |key, value| "#{CGI::escape(key.to_s)}=#{CGI::escape(value.to_s)}" }.join("&")
      end

      req = nil
      headers = {"User-Agent" => "Iterable API Ruby Client #{Iterable::VERSION}"}

      _uri  = URI.parse(uri)

      if method == 'POST'
        req = set_up_post_request(
          _uri, data, headers, binary_key
        )

      else
        request_uri = "#{_uri.path}?#{_uri.query}"
        if method == 'DELETE'
          req = Net::HTTP::Delete.new(request_uri, headers)
        else
          req = Net::HTTP::Get.new(request_uri, headers)
        end
      end

      begin
        http = Net::HTTP::Proxy(@proxy_host, @proxy_port).new(_uri.host, _uri.port)

        if _uri.scheme == 'https'
          http.ssl_version = :TLSv1
          http.use_ssl = true
          http.verify_mode = OpenSSL::SSL::VERIFY_NONE if @verify_ssl != true  # some openSSL client doesn't work without doing this
          http.ssl_timeout = @opts[:http_ssl_timeout] || 5
        end
        http.open_timeout = @opts[:http_open_timeout] || 5
        http.read_timeout = @opts[:http_read_timeout] || 10
        http.close_on_empty_response = @opts[:http_close_on_empty_response] || true

        response = http.start do
          http.request(req)
        end

      rescue Timeout::Error, Errno::ETIMEDOUT => e
        raise UnavailableError, "Timed out: #{_uri}"
      rescue => e
        raise ClientError, "Unable to open stream to #{_uri}: #{e.message}"
      end

      save_rate_limit_info(action, method, response)

      response.body || raise(ClientError, "No response received from stream: #{_uri}")
    end

    def http_multipart_request(uri, data)
      Net::HTTP::Post::Multipart.new url.path,
        "file" => UploadIO.new(data['file'], "application/octet-stream")
    end

    def prepare_json_payload(data)
      payload = {
        :api_key => @api_key,
        :format => 'json', #<3 XML
        :json => data.to_json
      }
      payload
    end

    def save_rate_limit_info(action, method, response)
      limit = response['x-rate-limit-limit'].to_i
      remaining = response['x-rate-limit-remaining'].to_i
      reset = response['x-rate-limit-reset'].to_i

      if limit.nil? or remaining.nil? or reset.nil?
          return
      end

      rate_info_key = get_rate_limit_info_key(action, method)
      @last_rate_limit_info[rate_info_key] = {
              limit: limit,
              remaining: remaining,
              reset: reset
      }
    end

    def get_rate_limit_info_key(endpoint, method)
      :"#{endpoint}_#{method.downcase}"
    end
  end
end

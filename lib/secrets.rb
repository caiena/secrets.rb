# frozen_string_literal: true

require "dotenv"
# TODO document this dotenv settings load
Dotenv.load ".env.#{ENV["APP_ENV"]}.local",
            ".env.local",
            ".env.#{ENV["APP_ENV"]}",
            ".env"

require_relative "secrets/secret"
require_relative "secrets/version"


#
# Secrets provides a simple way to use encryption/encoding on Stirngs.
#
module Secrets
  module_function

  # secrets standard error custom class
  class Error < StandardError; end

  def new(*args)
    Secret.new *args
  end

  def default_secret
    @default_secret ||= Secret.new ENV.fetch("SECRET_KEY")
  end

  def default_secret=(secret)
    @default_secret = secret
  end

  # :reek:ManualDispatch
  def method_missing(method_name, *args, &block)
    if default_secret.respond_to?(method_name)
      default_secret.public_send method_name, *args, &block
    else
      super
    end
  end

  # :reek:ManualDispatch
  def respond_to_missing?(method_name, include_private = false)
    default_secret.respond_to?(method_name) or super
  end

end

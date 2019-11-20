# frozen_string_literal: true

require "base64"
require "digest"
require "openssl"


module Secrets
  #
  # The Secret - an unknown device that masters obscure the art of message hashing and encrypting.
  #
  class Secret
    # custom error class for probles with pepper
    class PepperError < StandardError; end
    # custom error class for probles with salt
    class SaltError < StandardError; end
    # custom error class for probles with secret key
    class SecretKeyError < StandardError; end

    #
    # Seasoning provides salt and pepper flavor!
    #
    module Seasoning
      module_function

      def add_salt(value, salt:)
        # value + ":#{hashify(salt)}"
        value + ":#{salt}"
      end

      def remove_salt(value, salt:)
        # salt_part = ":#{hashify(salt)}"
        salt_part = ":#{salt}"
        raise SaltError, "bad salt" unless value.end_with? salt_part

        value.chomp salt_part
      end

      def add_pepper(value, pepper:)
        # value + "+#{hashify(pepper)}"
        value + "+#{pepper}"
      end

      def remove_pepper(value, pepper:)
        # pepper_part = "+#{hashify(pepper)}"
        pepper_part = "+#{pepper}"
        raise SaltError, "bad pepper" unless value.end_with? pepper_part

        value.chomp pepper_part
      end
    end


    #
    # Utilitary module to centralize base64 encoding and decoding with default custom options.
    # - it uses URL safe base64 encoding/decoding, allowing strings to be used in URLs
    # - it enforces UTF-8 encoding of encoded/decoded strings
    #
    module Base64Util
      module_function

      def encode(*args)
        Base64.urlsafe_encode64(*args).force_encoding("UTF-8")
      end

      def decode(*args)
        Base64.urlsafe_decode64(*args).force_encoding("UTF-8")
      end
    end


    def initialize(secret_key, pepper: nil)
      raise SecretKeyError, "secret key must be defined" if secret_key.to_s.strip.empty?

      @secret_key = secret_key
      @pepper     = pepper.to_s.strip.empty? ? nil : pepper
    end


    # Checks if tis secret uses a given key
    def key?(key)
      @secret_key == key
    end

    def pepper?(pepper)
      @pepper == pepper
    end


    # "hashes" the value - one-way cryptograhy
    # - generates a 44 character length string!
    def hashify!(value, salt: nil, pepper: @pepper)
      message = wrap_message(value, salt: salt, pepper: pepper)

      # using #secret as HMAC "key" - or hash "pepper"
      Base64Util.encode OpenSSL::HMAC.digest("SHA256", @secret_key, message)
    end
    alias hash! hashify!

    def hashify(*args)
      hashify! *args rescue nil
    end
    alias hash hashify


    # "encrypts" the value. It can be latter decrypted.
    def encrypt!(value, salt: nil, pepper: @pepper)
      message = wrap_message(value, salt: salt, pepper: pepper)

      # encrypt the message
      encrypted = cipher.update(message) + cipher.final
      cipher.reset

      Base64Util.encode encrypted
    end

    def encrypt(*args)
      encrypt! *args rescue nil
    end

    # "decrypts" an encrypted value.
    def decrypt!(value, salt: nil, pepper: @pepper)
      # value is base64 encoded - because it was previously encrypted by Magician
      encrypted = Base64Util.decode value

      # decrypt the message
      wrapped = decipher.update(encrypted) + decipher.final
      decipher.reset

      # removing pepper and salt
      unwrap_message(wrapped, salt: salt, pepper: pepper)
    end

    def decrypt(*args)
      decrypt! *args rescue nil
    end

    # :reek:UtilityFunction
    def compare(this, that)
      ActiveSupport::SecurityUtils.secure_compare(this, that)
      # or Rack::Utils.secure_compare(a, b)
    end


    private

    def cipher
      # create the cipher for encrypting
      @cipher ||= begin
        cipher = OpenSSL::Cipher.new("AES-256-CBC")
        cipher.encrypt

        # load key and iv into the cipher
        cipher.key = cipher_key
        cipher.iv  = cipher_iv

        cipher
      end
    end

    def decipher
      # create a cipher for decrypting
      @decipher ||= begin
        decipher = OpenSSL::Cipher.new("AES-256-CBC")
        decipher.decrypt

        # load the same key and iv into the cipher
        decipher.key = cipher_key
        decipher.iv  = cipher_iv

        decipher
      end
    end

    def cipher_key
      @cipher_key ||= Digest::SHA256.digest @secret_key
    end

    def cipher_iv
      # XXX: it can't be random because we would have different iv's across process/server restarts
      # @cipher_iv ||= OpenSSL::Random.random_bytes(16)
      # - MD5 produces a 16 bytes hash
      @cipher_iv ||= Digest::MD5.digest cipher_key
    end

    def wrap_message(value, salt: nil, pepper: @pepper)
      wrapped = Base64Util.encode(value)

      wrapped = Seasoning.add_salt(wrapped, salt: salt) if salt
      wrapped = Seasoning.add_pepper(wrapped, pepper: pepper) if pepper

      Base64Util.encode(wrapped)
    end

    def unwrap_message(value, salt: nil, pepper: @pepper)
      unwrapped = Base64Util.decode(value)

      unwrapped = Seasoning.remove_pepper(unwrapped, pepper: pepper) if pepper
      unwrapped = Seasoning.remove_salt(unwrapped, salt: salt) if salt

      Base64Util.decode(unwrapped)
    end
  end
end

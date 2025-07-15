# frozen_string_literal: true

lib = File.expand_path("lib", __dir__)
$LOAD_PATH.unshift(lib) unless $LOAD_PATH.include?(lib)
require "secrets/version"

Gem::Specification.new do |spec|
  spec.name          = "secrets"
  spec.version       = Secrets::VERSION
  spec.authors       = ["Pedro de Assis"]
  spec.email         = ["pedro@caiena.net"]

  spec.summary       = "Secrets - easily providing secrecy"
  spec.description   = "A set of predefined methods using specific algorithms to hash and/or encrypt/decrypt stuff"
  spec.homepage      = "https://github.com/caiena/secrets.rb"
  spec.license       = "MIT"

  spec.metadata["homepage_uri"] = spec.homepage
  spec.metadata["source_code_uri"] = "https://github.com/caiena/secrets.rb"
  # spec.metadata["changelog_uri"] = "TODO: Put your gem's CHANGELOG.md URL here."

  # Specify which files should be added to the gem when it is released.
  spec.files = Dir["lib/**/*", "exe/*", "README.md", "LICENSE.txt"]

  spec.bindir        = "exe"
  spec.executables   = spec.files.grep(%r{^exe/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.required_ruby_version = "~> 3.0"
end

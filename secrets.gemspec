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
  # The `git ls-files -z` loads the files in the RubyGem that have been added into git.
  spec.files = Dir.chdir(File.expand_path(__dir__)) do
    `git ls-files -z`.split("\x0").reject { |f| f.match(%r{^(test|spec|features)/}) }
  end
  spec.bindir        = "bin"
  spec.executables   = spec.files.grep(%r{^bin/}) { |f| File.basename(f) }
  spec.require_paths = ["lib"]

  spec.add_dependency "thor"

  spec.add_development_dependency "dotenv", "~> 2.7.6"
  spec.add_development_dependency "bundler", "~> 2.0"
  spec.add_development_dependency "guard-rspec"
  spec.add_development_dependency "pry-byebug"
  spec.add_development_dependency "rake", "~> 13.0"
  spec.add_development_dependency "rspec", "~> 3.9"
end

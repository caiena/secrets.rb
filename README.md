# Secrets

Secrets is a simples set of methods, within a single class (`Secrets::Secret`)
to easily provide simple secrecy through hashing and/or encryption.

- _hashing_ with `SHA256`
- _encryption_ with `AES-256-CBC`
- both _hashing_ and _encryption_ are wrapped in some "_url safe_" Base64 encoding/decoding
- resulting strings are enforced to `UTF-8`

## Installation

Add this line to your application's Gemfile:

```ruby
gem 'secrets'
```

And then execute:

    $ bundle

Or install it yourself as:

    $ gem install secrets

## Usage

`Secrets` comes with a default Secret (in `Secrets.default_secret`), and provides methods directly.
The _default_ secret key is fetched from `ENV["SECRET_KEY"]`.
```ruby
require "secrets"

# storing hashed passwords:
password_hash = Secrets.hash(plain_text_password)

# encrypting sensitive data
encrypted_credit_card = Secrets.encrypt(credit_card_number)

# even further with salt and/or pepper
user.encrypted_credit_card = Secrets.encrypt(credit_card_number, salt: user.salt, pepper: MyApp.pepper)
user.save

# and then, recover it
plain_credit_card = Secrets.decrypt(user.encrypted_credit_card, salt: user.salt, pepper: MyApp.pepper)
# and use it to call a paying service provider or whatever
```

You can override the _default secret_ if it suits you:
```ruby
my_special_secret = Secrets::Secret.new my_secret_key #, pepper: my_pepper
Secrets.default_secret = my_special_secret

Secrets.hash("message") # => will delegate hashing to my_special_secret
```

### Custom secrets

You can create multiple and/or custom secrets by instantiating `Secrets::Secret` directly:
```ruby
password_secret = Secrets::Secret.new ENV["PASSWORD_SECRET_KEY"]

user.password_hash = password_secret.hash(params[:password])

# with a default pepper defined on initialization - it'll be used by all methods if pepper: option is not used
credit_card_secret = Secrets::Secret.new ENV["SECRET_KEY"], pepper: ENV["CREDIT_CARD_PEPPER"]
user.encrypted_credit_card = credit_card_secret.encrypt(params[:credit_card_number])
```


## Alternatives

Here's a list of alternative _gems_ providing similar features:
- [`ActiveSupport::MessageEncryptor`](https://api.rubyonrails.org/v5.2.3/classes/ActiveSupport/MessageEncryptor.html).
- _more to be added_


## Development

After checking out the repo, run `bin/setup` to install dependencies. Then, run `rake spec` to run the tests. You can also run `bin/console` for an interactive prompt that will allow you to experiment.

To install this gem onto your local machine, run `bundle exec rake install`. To release a new version, update the version number in `version.rb`, and then run `bundle exec rake release`, which will create a git tag for the version, push git commits and tags, and push the `.gem` file to [rubygems.org](https://rubygems.org).

## Contributing

Bug reports and pull requests are welcome on GitHub at https://github.com/caiena/secrets.

## License

The gem is available as open source under the terms of the [MIT License](https://opensource.org/licenses/MIT).

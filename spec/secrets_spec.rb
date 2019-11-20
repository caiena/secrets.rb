# frozen_string_literal: true

RSpec.describe Secrets do
  it "has a version number" do
    expect(Secrets::VERSION).not_to be nil
  end

  it "has a default secret" do
    expect(Secrets.default_secret).to be_a Secrets::Secret
  end

  context "using default secret" do
    it "hashes messages" do
      args = ["message", salt: nil, pepper: "cayenne"]

      expect(Secrets.default_secret).to receive(:hashify).with(*args)
      Secrets.hashify *args
    end

    it "encrypts messages" do
      args = ["message", salt: nil, pepper: "cayenne"]

      expect(Secrets.default_secret).to receive(:encrypt).with(*args)
      Secrets.encrypt *args
    end

    it "decrypts messages" do
      args = ["message", salt: nil, pepper: "cayenne"]

      expect(Secrets.default_secret).to receive(:decrypt).with(*args)
      Secrets.decrypt *args
    end
  end
end

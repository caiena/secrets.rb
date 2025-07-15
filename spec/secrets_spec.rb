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
      expect(Secrets.default_secret).to receive(:hashify).with("message", salt: nil, pepper: "cayenne")
      Secrets.hashify "message", salt: nil, pepper: "cayenne"
    end

    it "encrypts messages" do
      expect(Secrets.default_secret).to receive(:encrypt).with("message", salt: nil, pepper: "cayenne")
      Secrets.encrypt "message", salt: nil, pepper: "cayenne"
    end

    it "decrypts messages" do
      expect(Secrets.default_secret).to receive(:decrypt).with("message", salt: nil, pepper: "cayenne")
      Secrets.decrypt "message", salt: nil, pepper: "cayenne"
    end
  end
end

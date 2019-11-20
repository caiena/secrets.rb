# frozen_string_literal: true

RSpec.describe Secrets::Secret do

  context "::new - instantiation" do
    it "requires a secret key" do
      expect { Secrets::Secret.new }.to raise_error ArgumentError

      key = "some-secret-key"
      secret = Secrets::Secret.new key
      expect(secret.key?(key)).to eq true
    end

    it "allows defining a pepper" do
      secret = Secrets::Secret.new "some-key", pepper: "some-pepper"
      expect(secret.pepper?("some-pepper")).to eq true

      other_secret = Secrets::Secret.new "some-key"
      secret_encrypted = secret.encrypt "value"

      expect(other_secret.decrypt(secret_encrypted, pepper: "some-pepper")).to eq "value"
    end

    it "ignores pepper if it's an empty string" do
      blank_peppers = [nil, "", "   "]
      secret = Secrets::Secret.new "some-key", pepper: blank_peppers.sample
      expect(secret.pepper?(nil)).to eq true
    end
  end

  # secret keys
  let(:secret_key)       { "some-key" }
  let(:other_secret_key) { "some-other-key" }

  # seasoning values
  let(:salt)         { "sea-salt"  }
  let(:other_salt)   { "pink-salt" }
  let(:pepper)       { "cayenne"   }
  let(:other_pepper) { "malagueta" }

  # messages - to be hashes or encrypted
  let(:message) { "something" }


  describe "hashing" do

    context "with secrets using the same secret key" do
      let(:secret_a) { described_class.new secret_key }
      let(:secret_b) { described_class.new secret_key }

      subject(:hash_a) { secret_a.hashify message }
      subject(:hash_b) { secret_b.hashify message }

      it "generates the same hash value" do
        expect(hash_a).to eq hash_b
      end

      context "with salt" do
        context "using the same salt" do
          subject(:hash_a) { secret_a.hashify message, salt: salt }
          subject(:hash_b) { secret_b.hashify message, salt: salt }

          it "generates the same hash value" do
            expect(hash_a).to eq hash_b
          end
        end

        context "using different salt" do
          subject(:hash_a) { secret_a.hashify message, salt: salt }
          subject(:hash_b) { secret_b.hashify message, salt: other_salt }

          it "generates different hash values" do
            expect(hash_a).not_to eq hash_b
          end
        end
      end

      context "with pepper" do
        context "using the same pepper" do
          subject(:hash_a) { secret_a.hashify message, pepper: pepper }
          subject(:hash_b) { secret_b.hashify message, pepper: pepper }

          it "generates the same hash value" do
            expect(hash_a).to eq hash_b
          end
        end

        context "using different pepper" do
          subject(:hash_a) { secret_a.hashify message, pepper: pepper }
          subject(:hash_b) { secret_b.hashify message, pepper: other_pepper }

          it "generates different hash values" do
            expect(hash_a).not_to eq hash_b
          end
        end
      end

      context "with salt and pepper" do
        context "using the same salt and pepper" do
          subject(:hash_a) { secret_a.hashify message, salt: salt, pepper: pepper }
          subject(:hash_b) { secret_b.hashify message, salt: salt, pepper: pepper }

          it "generates the same hash" do
            expect(hash_a).to eq hash_b
          end
        end

        context "using the same salt and different peppers" do
          subject(:hash_a) { secret_a.hashify message, salt: salt, pepper: pepper }
          subject(:hash_b) { secret_b.hashify message, salt: salt, pepper: other_pepper }

          it "generates different hashes" do
            expect(hash_a).not_to eq hash_b
          end
        end

        context "using the different salts and the same pepper" do
          subject(:hash_a) { secret_a.hashify message, salt: salt,       pepper: pepper }
          subject(:hash_b) { secret_b.hashify message, salt: other_salt, pepper: pepper }

          it "generates different hashes" do
            expect(hash_a).not_to eq hash_b
          end
        end
      end

    end # same secret key


    context "with secrets using different secret keys" do
      let(:secret_a) { described_class.new secret_key }
      let(:secret_b) { described_class.new other_secret_key }

      subject(:hash_a) { secret_a.hashify message }
      subject(:hash_b) { secret_b.hashify message }

      it "generates different hash values" do
        expect(hash_a).not_to eq hash_b
      end

      context "when keys have difference on letter case only" do
        let(:secret_a) { described_class.new "some-key" }
        let(:secret_b) { described_class.new "SoMe-kéy" }

        it "generates different hash values" do
          expect(hash_a).not_to eq hash_b
        end
      end

      context "when keys have difference on diacritics only" do
        let(:secret_a) { described_class.new "some-key_co" }
        let(:secret_b) { described_class.new "sómê-key_çõ" }

        it "generates different hash values" do
          expect(hash_a).not_to eq hash_b
        end
      end

      context "when keys have difference on letter case and diacritics" do
        let(:secret_a) { described_class.new "some-key_co" }
        let(:secret_b) { described_class.new "sÓmê-kEy_Çõ" }

        it "generates different hash values" do
          expect(hash_a).not_to eq hash_b
        end
      end

      context "with salt" do
        context "using the same salt" do
          subject(:hash_a) { secret_a.hashify message, salt: salt }
          subject(:hash_b) { secret_b.hashify message, salt: salt }

          it "generates the same hash value" do
            expect(hash_a).not_to eq hash_b
          end
        end

        context "using different salt" do
          subject(:hash_a) { secret_a.hashify message, salt: salt }
          subject(:hash_b) { secret_b.hashify message, salt: other_salt }

          it "generates different hash values" do
            expect(hash_a).not_to eq hash_b
          end
        end
      end

      context "with pepper" do
        context "using the same pepper" do
          subject(:hash_a) { secret_a.hashify message, pepper: pepper }
          subject(:hash_b) { secret_b.hashify message, pepper: pepper }

          it "generates the same hash value" do
            expect(hash_a).not_to eq hash_b
          end
        end

        context "using different pepper" do
          subject(:hash_a) { secret_a.hashify message, pepper: pepper }
          subject(:hash_b) { secret_b.hashify message, pepper: other_pepper }

          it "generates different hash values" do
            expect(hash_a).not_to eq hash_b
          end
        end
      end

      context "with salt and pepper" do
        context "using the same salt and pepper" do
          subject(:hash_a) { secret_a.hashify message, salt: salt, pepper: pepper }
          subject(:hash_b) { secret_b.hashify message, salt: salt, pepper: pepper }

          it "generates the same hash" do
            expect(hash_a).not_to eq hash_b
          end
        end

        context "using the same salt and different peppers" do
          subject(:hash_a) { secret_a.hashify message, salt: salt, pepper: pepper }
          subject(:hash_b) { secret_b.hashify message, salt: salt, pepper: other_pepper }

          it "generates different hashes" do
            expect(hash_a).not_to eq hash_b
          end
        end

        context "using the different salts and the same pepper" do
          subject(:hash_a) { secret_a.hashify message, salt: salt,       pepper: pepper }
          subject(:hash_b) { secret_b.hashify message, salt: other_salt, pepper: pepper }

          it "generates different hashes" do
            expect(hash_a).not_to eq hash_b
          end
        end
      end

    end # different secret keys

  end # hashing



  describe "encryption" do

    context "with secrets using the same secret key" do
      let(:secret_a) { described_class.new secret_key }
      let(:secret_b) { described_class.new secret_key }

      subject(:encrypted_a) { secret_a.encrypt message }
      subject(:encrypted_b) { secret_b.encrypt message }
      subject(:decrypted_a) { secret_a.decrypt encrypted_a }
      subject(:decrypted_b) { secret_b.decrypt encrypted_b }

      it "encrypts to the same value" do
        expect(encrypted_a).to eq encrypted_b
      end

      it "decrypts to the same value" do
        expect(decrypted_a).to eq message
        expect(decrypted_b).to eq message
      end

      it "can decrypt one another encrypted messages (because they're using the same secret key)" do
        expect(secret_a.decrypt(encrypted_b)).to eq message
        expect(secret_b.decrypt(encrypted_a)).to eq message
      end

      context "with salt" do
        context "using the same salt" do
          subject(:encrypted_a) { secret_a.encrypt message,     salt: salt }
          subject(:encrypted_b) { secret_b.encrypt message,     salt: salt }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, salt: salt }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, salt: salt }

          it "encrypts to the same value" do
            expect(encrypted_a).to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end

        context "using different salt" do
          subject(:encrypted_a) { secret_a.encrypt message,     salt: salt }
          subject(:encrypted_b) { secret_b.encrypt message,     salt: other_salt }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, salt: salt }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, salt: other_salt }

          it "encrypts to different values" do
            expect(encrypted_a).not_to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end
      end

      context "with pepper" do
        context "using the same pepper" do
          subject(:encrypted_a) { secret_a.encrypt message,     pepper: pepper }
          subject(:encrypted_b) { secret_b.encrypt message,     pepper: pepper }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, pepper: pepper }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, pepper: pepper }

          it "encrypts to the same value" do
            expect(encrypted_a).to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end

        context "using different pepper" do
          subject(:encrypted_a) { secret_a.encrypt message,     pepper: pepper }
          subject(:encrypted_b) { secret_b.encrypt message,     pepper: other_pepper }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, pepper: pepper }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, pepper: other_pepper }

          it "encrypts to different values" do
            expect(encrypted_a).not_to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end
      end

      context "with salt and pepper" do
        context "using the same salt and pepper" do
          subject(:encrypted_a) { secret_a.encrypt message,     salt: salt, pepper: pepper }
          subject(:encrypted_b) { secret_b.encrypt message,     salt: salt, pepper: pepper }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, salt: salt, pepper: pepper }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, salt: salt, pepper: pepper }

          it "encrypts to the same value" do
            expect(encrypted_a).to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end

        context "using the same salt and different peppers" do
          subject(:encrypted_a) { secret_a.encrypt message,     salt: salt, pepper: pepper }
          subject(:encrypted_b) { secret_b.encrypt message,     salt: salt, pepper: other_pepper }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, salt: salt, pepper: pepper }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, salt: salt, pepper: other_pepper }

          it "encrypts to different values" do
            expect(encrypted_a).not_to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end

        context "using the different salts and the same pepper" do
          subject(:encrypted_a) { secret_a.encrypt message,     salt: salt,       pepper: pepper }
          subject(:encrypted_b) { secret_b.encrypt message,     salt: other_salt, pepper: pepper }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, salt: salt,       pepper: pepper }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, salt: other_salt, pepper: pepper }

          it "encrypts to different values" do
            expect(encrypted_a).not_to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end
      end

    end # same secret key


    context "with secrets using different secret keys" do
      let(:secret_a) { described_class.new secret_key }
      let(:secret_b) { described_class.new other_secret_key }

      subject(:encrypted_a) { secret_a.encrypt message }
      subject(:encrypted_b) { secret_b.encrypt message }
      subject(:decrypted_a) { secret_a.decrypt encrypted_a }
      subject(:decrypted_b) { secret_b.decrypt encrypted_b }

      it "encrypts to different values" do
        expect(encrypted_a).not_to eq encrypted_b
      end

      it "decrypts to the same value" do
        expect(decrypted_a).to eq message
        expect(decrypted_b).to eq message
      end

      it "cannot decrypt one another encrypted messages (because they're using different secret keys)" do
        expect(secret_a.decrypt(encrypted_b)).not_to eq message
        expect(secret_b.decrypt(encrypted_a)).not_to eq message
      end

      context "when keys have difference on letter case only" do
        let(:secret_a) { described_class.new "some-key" }
        let(:secret_b) { described_class.new "SoMe-kéy" }

        it "encrypts to different values" do
          expect(encrypted_a).not_to eq encrypted_b
        end

        it "decrypts to the same value" do
          expect(decrypted_a).to eq message
          expect(decrypted_b).to eq message
        end
      end

      context "when keys have difference on diacritics only" do
        let(:secret_a) { described_class.new "some-key_co" }
        let(:secret_b) { described_class.new "sómê-key_çõ" }

        it "encrypts to different values" do
          expect(encrypted_a).not_to eq encrypted_b
        end

        it "decrypts to the same value" do
          expect(decrypted_a).to eq message
          expect(decrypted_b).to eq message
        end
      end

      context "when keys have difference on letter case and diacritics" do
        let(:secret_a) { described_class.new "some-key_co" }
        let(:secret_b) { described_class.new "sÓmê-kEy_Çõ" }

        it "encrypts to different values" do
          expect(encrypted_a).not_to eq encrypted_b
        end

        it "decrypts to the same value" do
          expect(decrypted_a).to eq message
          expect(decrypted_b).to eq message
        end
      end

      context "with salt" do
        context "using the same salt" do
          subject(:encrypted_a) { secret_a.encrypt message,     salt: salt }
          subject(:encrypted_b) { secret_b.encrypt message,     salt: salt }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, salt: salt }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, salt: salt }

          it "encrypts to different values" do
            expect(encrypted_a).not_to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end

        context "using different salt" do
          subject(:encrypted_a) { secret_a.encrypt message,     salt: salt       }
          subject(:encrypted_b) { secret_b.encrypt message,     salt: other_salt }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, salt: salt       }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, salt: other_salt }

          it "encrypts to different values" do
            expect(encrypted_a).not_to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end
      end

      context "with pepper" do
        context "using the same pepper" do
          subject(:encrypted_a) { secret_a.encrypt message,     pepper: pepper }
          subject(:encrypted_b) { secret_b.encrypt message,     pepper: pepper }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, pepper: pepper }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, pepper: pepper }

          it "encrypts to different values" do
            expect(encrypted_a).not_to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end

        context "using different pepper" do
          subject(:encrypted_a) { secret_a.encrypt message,     pepper: pepper }
          subject(:encrypted_b) { secret_b.encrypt message,     pepper: other_pepper }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, pepper: pepper }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, pepper: other_pepper }

          it "encrypts to different values" do
            expect(encrypted_a).not_to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end
      end

      context "with salt and pepper" do
        context "using the same salt and pepper" do
          subject(:encrypted_a) { secret_a.encrypt message,     salt: salt, pepper: pepper }
          subject(:encrypted_b) { secret_b.encrypt message,     salt: salt, pepper: pepper }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, salt: salt, pepper: pepper }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, salt: salt, pepper: pepper }

          it "encrypts to different values" do
            expect(encrypted_a).not_to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end

        context "using the same salt and different peppers" do
          subject(:encrypted_a) { secret_a.encrypt message,     salt: salt, pepper: pepper       }
          subject(:encrypted_b) { secret_b.encrypt message,     salt: salt, pepper: other_pepper }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, salt: salt, pepper: pepper       }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, salt: salt, pepper: other_pepper }

          it "encrypts to different values" do
            expect(encrypted_a).not_to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end

        context "using the different salts and the same pepper" do
          subject(:encrypted_a) { secret_a.encrypt message,     salt: salt,       pepper: pepper }
          subject(:encrypted_b) { secret_b.encrypt message,     salt: other_salt, pepper: pepper }
          subject(:decrypted_a) { secret_a.decrypt encrypted_a, salt: salt,       pepper: pepper }
          subject(:decrypted_b) { secret_b.decrypt encrypted_b, salt: other_salt, pepper: pepper }

          it "encrypts to different values" do
            expect(encrypted_a).not_to eq encrypted_b
          end

          it "decrypts to the same value" do
            expect(decrypted_a).to eq message
            expect(decrypted_b).to eq message
          end
        end
      end

    end # different secret keys

  end # encryption

end

# frozen_string_literal: true

require 'devise/strategies/authenticatable'
require 'eth'

module Devise
  module Strategies
    # Warden strategy to authenticate users via an Ethereum signature generated
    # by a browser wallet such as MetaMask.  The strategy expects three
    # parameters to be present in the request:
    #
    # * +metamask_address+  – the Ethereum address of the signer
    # * +metamask_message+  – the message that was signed (usually includes
    #   a timestamp and nonce)
    # * +metamask_signature+ – the signature produced by calling
    #   `ethereum.request({ method: 'personal_sign', params: [message, address] })`
    #
    # If the signature is valid for the given message and address, the user is
    # looked up (or created) and authenticated.  For additional security,
    # applications should store a unique nonce on each user and require that
    # the signed message contain this nonce along with a timestamp.  This
    # strategy does not enforce a specific message format – it merely
    # recovers the signer from the signature and compares it to the supplied
    # address.  Implementers may override +valid_message?+ to enforce
    # application‑specific requirements.
    class MetamaskAuthenticatable < Authenticatable
      # The name of the parameters expected in the HTTP request.  Developers can
      # override these on a per‑application basis via Devise configuration:
      #
      #   Devise.setup do |config|
      #     config.metamask_address_param  = 'address'
      #     config.metamask_message_param  = 'message'
      #     config.metamask_signature_param = 'signature'
      #   end
      METAMASK_ADDRESS_PARAM  = (Devise.respond_to?(:metamask_address_param)  ? Devise.metamask_address_param  : 'metamask_address').freeze
      METAMASK_MESSAGE_PARAM  = (Devise.respond_to?(:metamask_message_param)  ? Devise.metamask_message_param  : 'metamask_message').freeze
      METAMASK_SIGNATURE_PARAM = (Devise.respond_to?(:metamask_signature_param) ? Devise.metamask_signature_param : 'metamask_signature').freeze

      # Determine whether this strategy is applicable to the current request.
      # We override +valid?+ so that Warden runs the strategy whenever the
      # MetaMask parameters are present at the top level, even if the default
      # Devise params (like `user[email]`) are missing.
      def valid?
        metamask_address.present? && metamask_message.present? && metamask_signature.present?
      end

      # Entry point for the Warden strategy.  If the MetaMask parameters are
      # missing, we simply pass and allow other strategies to handle the
      # request.  Otherwise we recover the Ethereum address from the signature
      # and, if it matches, authenticate the corresponding user.
      def authenticate!
        return pass if metamask_address.blank? || metamask_message.blank? || metamask_signature.blank?

        unless valid_signature?
          return fail!(:invalid_signature)
        end

        resource = mapping.to.find_by(eth_address_attribute => normalized_address)
        unless resource
          # Applications can override this behaviour by defining a class method
          # called +from_metamask+ on their resource (e.g. User.from_metamask)
          # that returns a new or existing resource.  If not defined, the
          # record will be created using the eth_address attribute.
          if mapping.to.respond_to?(:from_metamask)
            resource = mapping.to.from_metamask(normalized_address, metamask_message)
          else
            resource = mapping.to.new(eth_address_attribute => normalized_address)
            resource.save if resource.respond_to?(:save)
          end
        end

        if resource
          # Allow applications to handle nonce rotation after successful login.
          resource.rotate_metamask_nonce if resource.respond_to?(:rotate_metamask_nonce)
          success!(resource)
        else
          fail!(:invalid)
        end
      end

      private

      # Helper to fetch the parameter values from the Rack request.
      def metamask_address
        params[METAMASK_ADDRESS_PARAM]
      end

      def metamask_message
        params[METAMASK_MESSAGE_PARAM]
      end

      def metamask_signature
        params[METAMASK_SIGNATURE_PARAM]
      end

      # Normalise the supplied address (downcase and strip 0x prefix).
      def normalized_address
        @normalized_address ||= begin
          addr = metamask_address.to_s.downcase
          addr.start_with?('0x') ? addr[2..] : addr
        end
      end

      # Attribute name used to store the Ethereum address on the resource.  By
      # default the gem looks for +eth_address+ on the model.  Applications can
      # override this by setting +devise_metamask_eth_attribute+ on Devise.
      def eth_address_attribute
        if Devise.respond_to?(:metamask_eth_attribute)
          Devise.metamask_eth_attribute
        else
          :eth_address
        end
      end

      # Returns true if the signature belongs to the supplied address.  Uses
      # eth gem's personal_sign recovery to derive the public key from the
      # signature and message, then converts it into an address.
      def valid_signature?
        begin
          # MetaMask signs hex‑encoded messages by default. If the supplied
          # message starts with "0x", it represents a UTF‑8 message encoded as
          # hex; decode it back into a plain string before attempting
          # signature recovery. Otherwise use the message verbatim.  See
          # MetaMask docs: for historical reasons, personal_sign data must be
          # hex‑encoded【256823775269663†L300-L334】.
          msg = metamask_message.to_s
          if msg.start_with?('0x')
            # Drop the 0x prefix and pack hex into binary, then force
            # encoding to UTF‑8.  If decoding fails, fall back to the raw
            # string.
            begin
              hex = msg[2..]
              binary = [hex].pack('H*')
              msg = binary.force_encoding('UTF-8')
            rescue StandardError
              msg = metamask_message
            end
          end
          # Recover the public key using Eth::Signature rather than
          # Eth::Key.  The Signature module provides helpers for
          # personal_sign recovery (EIP‑191)【369635869403598†L156-L198】.
          recovered_public_key = Eth::Signature.personal_recover(msg, metamask_signature)
          recovered_address = Eth::Utils.public_key_to_address(recovered_public_key).downcase
          recovered_address_without_prefix = recovered_address.start_with?('0x') ? recovered_address[2..] : recovered_address
          normalized_address == recovered_address_without_prefix && valid_message?
        rescue StandardError
          false
        end
      end

      # Overridable hook to validate the contents of the signed message.
      # By default it returns true.  Applications can override this by
      # monkey‑patching the strategy class or by subclassing.  A typical
      # implementation would extract a timestamp and nonce and ensure the
      # message is recent and contains the nonce stored on the resource.
      def valid_message?
        # If allowed networks are configured, require the message to include a
        # network name and ensure it matches the whitelist.  The message is
        # expected to be comma‑separated with four parts: title, timestamp,
        # nonce and network.  If no networks are configured, accept any
        # message.
        allowed = Devise.respond_to?(:metamask_allowed_networks) ? Devise.metamask_allowed_networks : []
        return true if allowed.nil? || allowed.empty?
        parts = metamask_message.to_s.split(',')
        return false unless parts.length >= 4
        network = parts.last.to_s.downcase.strip
        allowed.map(&:downcase).include?(network)
      end
    end
  end
end

Warden::Strategies.add(:metamask_authenticatable, Devise::Strategies::MetamaskAuthenticatable)
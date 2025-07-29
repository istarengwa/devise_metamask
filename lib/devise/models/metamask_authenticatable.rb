# frozen_string_literal: true

require 'active_support/concern'
require 'securerandom'

module Devise
  module Models
    # Mixin for models that want to be authenticatable via an Ethereum wallet.
    # This module provides helper methods to manage a per‑user nonce used in
    # signed messages and basic validations for the Ethereum address.  Models
    # including this module must add `:metamask_authenticatable` to their
    # devise call, e.g.:
    #
    #   class User < ApplicationRecord
    #     devise :metamask_authenticatable, :registerable, :trackable
    #   end
    #
    # The model must have an attribute called +eth_address+ (or the
    # attribute specified via Devise.metamask_eth_attribute) and an attribute
    # called +metamask_nonce+ to store a randomly generated value.  The nonce
    # should be included in the message signed by the user and rotated after
    # each successful login to prevent replay attacks.
    module MetamaskAuthenticatable
      extend ActiveSupport::Concern

      included do
        # Ensure the Ethereum address and nonce exist and are unique
        validates eth_attribute, presence: true, uniqueness: true, if: -> { respond_to?(eth_attribute) }
        validates nonce_attribute, presence: true, if: -> { respond_to?(nonce_attribute) }

        # Assign a nonce on creation if it doesn't exist
        before_validation :ensure_metamask_nonce, on: :create
      end

      class_methods do
        # Return the name of the attribute used to store the user's Ethereum
        # address.  Falls back to :eth_address when no custom attribute has been
        # defined via Devise.metamask_eth_attribute.
        def eth_attribute
          if Devise.respond_to?(:metamask_eth_attribute)
            Devise.metamask_eth_attribute.to_sym
          else
            :eth_address
          end
        end

        # Return the name of the attribute used to store the nonce.  You can
        # override this by defining Devise.metamask_nonce_attribute.
        def nonce_attribute
          if Devise.respond_to?(:metamask_nonce_attribute)
            Devise.metamask_nonce_attribute.to_sym
          else
            :metamask_nonce
          end
        end

        # Find or create a record from a MetaMask login.  Applications can
        # override this method to implement custom user lookup and creation
        # logic.  The default behaviour simply finds the record by Ethereum
        # address and, if none exists, builds a new record with the address and
        # an initial nonce.
        def from_metamask(address, _message)
          addr = address.to_s.downcase.sub(/^0x/, '')
          user = find_by(eth_attribute => addr)
          return user if user
          new_user = new(eth_attribute => addr)
          # Assign a placeholder email and password if the model has these
          # attributes and they are blank.  This helps satisfy Devise
          # validations provided by :database_authenticatable and :validatable.
          if new_user.respond_to?(:email) && new_user.email.blank?
            new_user.email = "#{addr}@metamask.local"
          end
          if new_user.respond_to?(:password)
            random_password = SecureRandom.hex(16)
            new_user.password = random_password
            if new_user.respond_to?(:password_confirmation)
              new_user.password_confirmation = random_password
            end
          end
          # Ensure the nonce is set before saving
          new_user.send(:ensure_metamask_nonce)
          new_user.save
          new_user
        end
      end

      # Rotate the nonce after a successful authentication.  This method
      # generates a new random value and saves the record.  Applications can
      # override this in their model to customise nonce rotation behaviour.
      def rotate_metamask_nonce
          send("#{nonce_attribute}=", SecureRandom.uuid)
          save
      end

      private

      # Ensure the nonce attribute has a value.  Generates a UUID if nil.
      def ensure_metamask_nonce
        current = send(nonce_attribute)
        send("#{nonce_attribute}=", SecureRandom.uuid) if current.blank?
      end

      # Delegate attribute accessors to the class methods defined above
      def eth_attribute
        self.class.eth_attribute
      end

      def nonce_attribute
        self.class.nonce_attribute
      end

      public

      # Return true if this record has an Ethereum address.  Applications can
      # use this helper in views to determine whether a user authenticated via
      # MetaMask.  For example, you can hide email/password fields when
      # +metamask_user?+ returns true.
      def metamask_user?
        addr_attr = self.class.eth_attribute
        respond_to?(addr_attr) && send(addr_attr).present?
      end

      # Devise calls this method to determine whether an e‑mail is required.
      # We bypass the requirement for MetaMask users so they can be created
      # without an e‑mail address when :validatable is enabled.  Override in
      # your model if you need different behaviour.
      def email_required?
        return false if metamask_user?
        super
      end if method_defined?(:email_required?)

      # Devise calls this method to determine whether a password is required.
      # Skip password requirement for MetaMask users.  This allows accounts
      # created via MetaMask to be saved without a password.  Override if
      # necessary.  Note that Devise controllers may still ask for the
      # current password when updating sensitive attributes; see the README
      # for guidance on overriding Devise::RegistrationsController.
      def password_required?
        return false if metamask_user?
        super
      end if method_defined?(:password_required?)
    end
  end
end
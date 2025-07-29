# frozen_string_literal: true

require 'devise'
require 'devise/strategies/metamask_authenticatable'

module DeviseMetamask
  # Expose the gem version
  require_relative 'devise_metamask/version'

  # Define a configuration accessor on Devise for allowed networks.  When set
  # to an array of strings, the strategy will only accept messages signed for
  # these networks.  The network is expected to be included as the last
  # component of the signed message (e.g. "MyApp,1679876543210,nonce,base").
  unless Devise.respond_to?(:metamask_allowed_networks)
    Devise.singleton_class.attr_accessor :metamask_allowed_networks
    Devise.metamask_allowed_networks = []
  end

  # Register the :metamask_authenticatable module with Devise.  When this gem
  # is loaded, Devise will recognise the module and make it available in the
  # devise declaration in your models, e.g.:
  #
  #   devise :metamask_authenticatable, :registerable, ...
  #
  Devise.add_module(
    :metamask_authenticatable,
    strategy: true,
    model: 'devise/models/metamask_authenticatable'
  )
end
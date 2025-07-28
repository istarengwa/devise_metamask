# frozen_string_literal: true

require 'devise'
require 'devise/strategies/metamask_authenticatable'

module DeviseMetamask
  # Expose the gem version
  require_relative 'devise_metamask/version'

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
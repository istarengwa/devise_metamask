# frozen_string_literal: true

require 'rails/generators'
require 'rails/generators/migration'

module Devise
  module Generators
    # Generator to set up MetaMask authentication in a Rails application.  It
    # creates an initializer with default configuration, a migration to add
    # Ethereum address and nonce fields to your users table, and attempts to
    # inject the :metamask_authenticatable module into your user model.
    #
    # You can run this generator with:
    #
    #   rails generate devise:metamask
    #
    # or explicitly with the `init` task:
    #
    #   rails generate devise:metamask init
    #
    class MetamaskGenerator < Rails::Generators::Base
      include Rails::Generators::Migration

      source_root File.expand_path('templates', __dir__)

      desc 'Add MetaMask authentication support to a Devise-enabled model.'

      # The primary task.  Accepts an optional model name, defaulting to
      # 'User'.  We use a named argument so that rails g devise:metamask
      # Admin will install MetaMask on the Admin model.
      argument :model_name, type: :string, default: 'User', banner: 'model'

      def install_initializer
        template 'devise_metamask.rb.erb', 'config/initializers/devise_metamask.rb'
      end

      def create_migration_file
        migration_template 'add_metamask_fields.rb.erb', "db/migrate/add_#{file_name}_metamask_fields.rb"
      end

      def inject_devise_module
        model_path = File.join('app', 'models', "#{file_name}.rb")
        unless File.exist?(model_path)
          say_status :error, "Model #{class_name} does not exist. Please create it and include Devise first."
          return
        end
        if File.read(model_path).match?(/:metamask_authenticatable/)
          say_status :identical, "#{model_path}", :blue
        else
          # Inject the module into the devise declaration.  This naïvely looks
          # for the first occurrence of 'devise' and inserts the symbol.  If
          # devise is called on multiple lines, this may need manual editing.
          inject_into_file model_path,
                           ', :metamask_authenticatable',
                           after: /devise[^\n]*/
          say_status :insert, "Added :metamask_authenticatable to #{model_path}", :green
        end
      end

      private

      # Convert model name to underscore file name
      def file_name
        model_name.underscore
      end

      # Convert model name to class name
      def class_name
        model_name.camelize
      end

      # Generate a unique migration number
      def self.next_migration_number(dirname)
        Time.now.utc.strftime('%Y%m%d%H%M%S').next
      end
    end
  end
end
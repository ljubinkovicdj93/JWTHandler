Pod::Spec.new do |spec|

  spec.name         = "JWTHandler"
  spec.version      = "1.0.0"
  spec.summary      = "Handler for incoming JWT's. Decodes JWT, saves it to keychain, etc..."

  spec.description  = "Handler for incoming JWT's. Decodes JWT, saves it to keychain, etc... Add more here..."

  spec.homepage     = "https://github.com/ljubinkovicdj93/JWTHandler"

  spec.license      = "MIT"

  spec.author       = { "Djordje Ljubinkovic" => "ljubinkovicdj93@gmail.com" }

  spec.platform		= :ios, "12.2"

  spec.source       = { :git => "https://github.com/ljubinkovicdj93/JWTHandler.git", :tag => "#{spec.version}" }

  spec.source_files  = "JWTHandler/**/*"

  spec.swift_version = "5.0"
end

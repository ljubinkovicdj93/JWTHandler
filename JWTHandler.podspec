Pod::Spec.new do |spec|

  spec.name         = "JWTHandler"
  spec.version      = "0.0.1"
  spec.summary      = "A short description of JWTHandler."

  spec.description  = <<-DESC
                   DESC

  spec.homepage     = "http://EXAMPLE/JWTHandler"

  spec.license      = "MIT (example)"
  # spec.license      = { :type => "MIT", :file => "FILE_LICENSE" }

  spec.author             = { "Djordje Ljubinkovic" => "djordje.ljubinkovic@symphony.is" }

  spec.source       = { :git => "http://EXAMPLE/JWTHandler.git", :tag => "#{spec.version}" }

  spec.source_files  = "Classes", "Classes/**/*.{h,m}"
  spec.exclude_files = "Classes/Exclude"
end

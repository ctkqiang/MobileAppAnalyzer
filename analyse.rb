# 引入所需的库
require "open-uri"
require "fileutils"
require "git"
require "rbconfig"

# MobileAppAnalyzer 类用于分析移动应用文件（APK 和 IPA）
class MobileAppAnalyzer
    attr_accessor :file_path, :output_dir
    
    def initialize(file_path, output_dir)
        @file_path = file_path
        @output_dir = output_dir

        # Android 和 iOS 的文件扩展名
        @android_extension = ".apk"
        @ios_extension = ".ipa"

        # 工具的 URL
        @apktool = "https://github.com/iBotPeaches/Apktool.git"
        @apktool_bin = "https://github.com/iBotPeaches/Apktool/releases/download/v2.9.3/apktool_2.9.3.jar"
        @frida = "https://github.com/frida/frida.git"
        @jadx = "https://github.com/skylot/jadx.git"

        @tools = "tools/"

        @os = get_os
    end

  # 运行分析器的主要方法
  def run
    begin
        get_tools
        
        if @file_path.end_with?(@android_extension)
            analyse_android
        elsif @file_path.end_with?(@ios_extension)
            analyse_ios
        else
            puts "不支持的文件格式。请提供 APK 或 IPA 文件"
        end
        rescue => error
        puts "发生错误：#{error.message}"
        end
  end

  private

  # 执行 shell 命令并显示输出的方法
  def run_command(command)
    puts "正在运行：#{command}"

    output = `#{command}`
    puts output
    
    output
  end

  # 分析 Android APK 文件的方法
  def analyse_android
    extract_apk
    run_apktool
    run_jadx

    puts "Android APK 分析成功完成。"
  end

  # 分析 iOS IPA 文件的方法
  def analyse_ios
    extract_ipa
    binary_path = find_mach_o_binary
    
    run_class_dump(binary_path)

    puts "iOS IPA 分析成功完成。"
  end

  # 提取 APK 文件的方法
  def extract_apk
    FileUtils.mkdir_p(@output_dir)
    run_command("unzip #{@file_path} -d #{@output_dir}")
  end

  # 提取 IPA 文件的方法
  def extract_ipa
    FileUtils.mkdir_p(@output_dir)
    run_command("unzip #{@file_path} -d #{@output_dir}")
  end

  # 在 APK 文件上运行 APKTool 的方法
  def run_apktool
    apktool_output_dir = File.join(@output_dir, "apktool-output")
    run_command("java -jar #{File.join(@tools, 'Apktool', 'apktool_2.9.3.jar')} d #{@file_path} -o #{apktool_output_dir}")
  end

  # 在 APK 文件上运行 JADX 的方法
  def run_jadx
    jadx_output_dir = File.join(@output_dir, "jadx-output")
    run_command("jadx -d #{jadx_output_dir} #{@file_path}")
  end

  # 下载和克隆必要工具的方法
  def get_tools
    FileUtils.mkdir_p(@tools)

    apktool_existed = system("which apktool > /dev/null 2>&1")
    
    if get_os == "mac" && !apktool_existed
        run_command("brew install apktool")
    else
        unless File.exist?(File.join(@tools, 'Apktool'))
            Git.clone(@apktool, "#{@tools}/Apktool")
        
            puts "正在克隆 Apktool..."
        
            download(@apktool_bin, "#{@tools}/Apktool/apktool_2.9.3.jar")
        else
            puts "Apktool 已存在"
        end
    end

    unless File.exist?(File.join(@tools, 'frida'))
      Git.clone(@frida, "#{@tools}/frida")

      puts "正在克隆 Frida..."
    else
      puts "Frida 已存在"
    end

    unless File.exist?(File.join(@tools, 'jadx'))
      Git.clone(@jadx, "#{@tools}/jadx")

      puts "正在克隆 JADX..."
      
      if @os == "mac"
        run_command("brew install jadx")
      else
        run_command("cd #{@tools}/jadx && ./gradlew dist")
      end
    
    else
      puts "JADX 已存在"
    end
  end

  # 从 URL 下载文件的方法
  def download(url, path)
    case io = URI.open(url)
    
    when StringIO then File.open(path, "w") { |f| f.write(io.read) }
    when Tempfile then io.close; FileUtils.mv(io.path, path)

    end
  end

  # 在 iOS 二进制文件上运行 class-dump 的方法
  def run_class_dump(binary_path)
    header_dir = File.join(@output_dir, "headers")
    
    FileUtils.mkdir_p(header_dir)
    run_command("class-dump -H -o #{header_dir} #{binary_path}")
  end

  # 确定操作系统的方法
  def get_os
    host_os = RbConfig::CONFIG["host_os"]

    case host_os
    when /mswin|msys|mingw|cygwin|bccwin|wince|emc/
      "win"
    when /darwin|mac os/
      "mac"
    when /linux/
      "linux"
    when /solaris|bsd/
      "bsd"
    else
      "error"
    end
  end

  # 在 IPA 文件中找到 Mach-O 二进制文件的方法
  def find_mach_o_binary
    # 实现在提取的 IPA 中找到 Mach-O 二进制文件的逻辑
    # 这是一个占位符实现
    File.join(@output_dir, "Payload", "*.app", "*")
  end
end

# 解析命令行参数
if ARGV.length != 2
  puts "用法：ruby analyse.rb <file_path> <output_dir>"
  exit
end

file_path = ARGV[0]
output_dir = ARGV[1]

if file_path == "-h" || file_path == "--help"
  puts "用法：ruby analyse.rb <file_path> <output_dir>"
  exit
end

# 实例化并运行分析器
analyzer = MobileAppAnalyzer.new(file_path, output_dir)
analyzer.run

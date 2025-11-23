#include <boost/program_options.hpp>
#include <iostream>

#include "cmd_options.h"

namespace po = boost::program_options;

namespace CryptoGuard {

ProgramOptions::ProgramOptions() {
        desc_.add_options()
            ("help", "список доступных опций")
            ("command", po::value<std::string>(), "команда encrypt, decrypt или checksum")
            ("input", po::value<std::string>(), "путь до входного файла")
            ("output", po::value<std::string>(), "путь до файла, в котором будет сохранён результат")
            ("password", po::value<std::string>(), "пароль для шифрования");
}

ProgramOptions::~ProgramOptions() = default;

void ProgramOptions::Parse(int argc, char *argv[]) {
    po::variables_map vm;
    po::store(po::parse_command_line(argc, argv, desc_), vm);
    po::notify(vm);

    if (vm.count("help")) {
        std::cout << desc_ << "\n";
        exit(0);
        return;
    }

    if (vm.count("command")) {
        std::string cmd = vm["command"].as<std::string>();
        auto it = commandMapping_.find(cmd);
        if (it != commandMapping_.end()) {
            command_ = it->second;
        } else {
            throw std::invalid_argument("Unknown command: " + cmd);
        }
    }
    
    if (vm.count("input")) {
        inputFile_ = vm["input"].as<std::string>();
    }
    
    if (vm.count("output")) {
        outputFile_ = vm["output"].as<std::string>();
    }
    
    if (vm.count("password")) {
        password_ = vm["password"].as<std::string>();
    }
}

}  // namespace CryptoGuard

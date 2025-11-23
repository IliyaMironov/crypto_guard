#include <gtest/gtest.h>
#include "../include/cmd_options.h"

TEST(ProgramOptions, ParseHelpOption) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {"program", "--help"};
    EXPECT_NO_THROW(options.Parse(2, const_cast<char**>(argv)));
}

TEST(ProgramOptions, ParseEncryptCommand) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {"program", "--command", "encrypt"};
    options.Parse(3, const_cast<char**>(argv));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
}

TEST(ProgramOptions, ParseDecryptCommand) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {"program", "--command", "decrypt"};
    options.Parse(3, const_cast<char**>(argv));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT);
}

TEST(ProgramOptions, ParseChecksumCommand) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {"program", "--command", "checksum"};
    options.Parse(3, const_cast<char**>(argv));
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM);
}

TEST(ProgramOptions, ParseInvalidCommand) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {"program", "--command", "invalid"};
    EXPECT_THROW(options.Parse(3, const_cast<char**>(argv)), std::invalid_argument);
}

TEST(ProgramOptions, ParseWithAllOptions) {
    CryptoGuard::ProgramOptions options;
    const char* argv[] = {"program", "--command", "encrypt", "--input", "input.txt", "--output", "output.txt", "--password", "secret"};
    options.Parse(9, const_cast<char**>(argv));
    
    EXPECT_EQ(options.GetCommand(), CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT);
    EXPECT_EQ(options.GetInputFile(), "input.txt");
    EXPECT_EQ(options.GetOutputFile(), "output.txt");
    EXPECT_EQ(options.GetPassword(), "secret");
}

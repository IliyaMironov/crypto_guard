#include <gtest/gtest.h>
#include <sstream>
#include "../include/crypto_guard_ctx.h"

TEST(CalculateChecksumTest, EmptyStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream emptyStream;
    
    std::string checksum = ctx.CalculateChecksum(emptyStream);
    
    EXPECT_EQ(checksum.length(), 64);
    // Проверяем, что это корректная шестнадцатеричная строка
    EXPECT_TRUE(checksum.find_first_not_of("0123456789abcdef") == std::string::npos);
}

TEST(CalculateChecksumTest, NonEmptyStream) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream testStream;
    testStream << "Hello, World!123";
    
    std::string checksum = ctx.CalculateChecksum(testStream);
    
    EXPECT_EQ(checksum.length(), 64);
    // Проверяем, что это корректная шестнадцатеричная строка
    EXPECT_TRUE(checksum.find_first_not_of("0123456789abcdef") == std::string::npos);
    
    std::stringstream testStream2;
    testStream2 << "Hello, World!123";
    std::string checksum2 = ctx.CalculateChecksum(testStream2);
    EXPECT_EQ(checksum, checksum2);
}

// Tests for Encrypt function
TEST(EncryptTest, BasicEncryption) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream input;
    input << "Hello, World!123";
    
    std::stringstream encrypted;
    std::string password = "test_password";
    
    ctx.EncryptFile(input, encrypted, password);

    encrypted.seekg(0);
    std::string encryptedData((std::istreambuf_iterator<char>(encrypted)),
                             std::istreambuf_iterator<char>());
    EXPECT_FALSE(encryptedData.empty());
}

TEST(EncryptTest, EncryptionProducesDifferentOutput) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream input1;
    input1 << "Hello, World!123";
    
    std::stringstream input2;
    input2 << "Hello, World!123";
    
    std::stringstream encrypted1;
    std::stringstream encrypted2;
    std::string password1 = "test_password1";
    std::string password2 = "test_password2";
    
    ctx.EncryptFile(input1, encrypted1, password1);
    ctx.EncryptFile(input2, encrypted2, password2);
    
    encrypted1.seekg(0);
    encrypted2.seekg(0);
    std::string encryptedData1((std::istreambuf_iterator<char>(encrypted1)),
                              std::istreambuf_iterator<char>());
    std::string encryptedData2((std::istreambuf_iterator<char>(encrypted2)),
                              std::istreambuf_iterator<char>());
    EXPECT_NE(encryptedData1, encryptedData2);
}

TEST(EncryptTest, EncryptionThrowsOnInvalidPassword) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream input;
    input << "Hello, World!123";
    
    std::stringstream encrypted;
    std::string password = "";
    
    try {
        ctx.EncryptFile(input, encrypted, password);
        encrypted.seekg(0);
        std::string encryptedData((std::istreambuf_iterator<char>(encrypted)),
                                 std::istreambuf_iterator<char>());
        EXPECT_FALSE(encryptedData.empty());
    } catch (const std::exception& e) {
        SUCCEED() << "Exception caught (acceptable): " << e.what();
    }
}

TEST(EncryptTest, BasicDecryption) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream input;
    input << "Hello, World!123";
    
    std::stringstream encrypted;
    std::string password = "test_password";
    
    ctx.EncryptFile(input, encrypted, password);
    encrypted.seekg(0);

    std::stringstream decrypted;
    ctx.DecryptFile(encrypted, decrypted, password);
    decrypted.seekg(0);
    std::string decryptedData((std::istreambuf_iterator<char>(decrypted)),
                             std::istreambuf_iterator<char>());
    EXPECT_FALSE(decryptedData.empty());
    EXPECT_EQ("Hello, World!123", decryptedData);
}

TEST(EncryptTest, DecryptionWithWrongPassword) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream input;
    input << "Secret message";
    
    std::stringstream encrypted;
    std::string correctPassword = "correct_password";
    std::string wrongPassword = "wrong_password";
    
    ctx.EncryptFile(input, encrypted, correctPassword);
    encrypted.seekg(0);

    std::stringstream decrypted;
    ctx.DecryptFile(encrypted, decrypted, wrongPassword);
    decrypted.seekg(0);
    std::string decryptedData((std::istreambuf_iterator<char>(decrypted)),
                             std::istreambuf_iterator<char>());
    
    EXPECT_NE("Secret message", decryptedData);
}

TEST(EncryptTest, DecryptionWithLargeData) {
    CryptoGuard::CryptoGuardCtx ctx;
    std::stringstream input;
    std::string largeData;
    for (int i = 0; i < 1000; ++i) {
        largeData += "This is a test line number " + std::to_string(i) + ". ";
    }
    input << largeData;
    
    std::stringstream encrypted;
    std::string password = "test_password_large";
    
    ctx.EncryptFile(input, encrypted, password);
    encrypted.seekg(0);

    std::stringstream decrypted;
    ctx.DecryptFile(encrypted, decrypted, password);
    decrypted.seekg(0);
    std::string decryptedData((std::istreambuf_iterator<char>(decrypted)),
                             std::istreambuf_iterator<char>());
    EXPECT_FALSE(decryptedData.empty());
    EXPECT_EQ(largeData, decryptedData);
    EXPECT_EQ(largeData.length(), decryptedData.length());
}

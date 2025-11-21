#include "crypto_guard_ctx.h"
#include <openssl/evp.h>
#include <vector>
#include <memory>
#include <iomanip>
#include <sstream>

namespace CryptoGuard {
    struct AesCipherParams {
        static const size_t KEY_SIZE = 32;             // AES-256 key size
        static const size_t IV_SIZE = 16;              // AES block size (IV length)
        const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm

        int encrypt;                              // 1 for encryption, 0 for decryption
        std::array<unsigned char, KEY_SIZE> key;  // Encryption key
        std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    };

    class CryptoGuardCtx::Impl {
    public:
        Impl();
        ~Impl();
        void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
        void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password);
        std::string CalculateChecksum(std::iostream &inStream);
        AesCipherParams CreateChiperParamsFromPassword(std::string_view password);
    private:
        void CryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password, int encrypt);
    };

    CryptoGuardCtx::Impl::Impl() {};
    CryptoGuardCtx::Impl::~Impl() {};
    
    void CryptoGuardCtx::Impl::CryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password, int encrypt) {
        if (inStream.bad()) {
            throw std::runtime_error("Error reading from input stream");
        }
        if (outStream.bad()) {
            throw std::runtime_error("Error writing to output stream");
        }

        auto params = CreateChiperParamsFromPassword(password);
        params.encrypt = encrypt;
    
        // Создаем контекст шифра
        auto* rawCtx = EVP_CIPHER_CTX_new();
        if (!rawCtx) {
            throw std::runtime_error("Failed to create cipher context");
        }

        auto evpDeleter = [](EVP_CIPHER_CTX *ctx){ EVP_CIPHER_CTX_free(ctx); };
        std::unique_ptr<EVP_CIPHER_CTX, decltype(evpDeleter)> ctx{ rawCtx, evpDeleter };

        if(!EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
            throw std::runtime_error("Failed to initialize encryption context");
        }

        std::vector<unsigned char> outBuf(4096 + EVP_MAX_BLOCK_LENGTH);
        std::vector<unsigned char> inBuf(4096);
        int outLen;

        while (inStream.read(reinterpret_cast<char*>(inBuf.data()), 4096) || inStream.gcount() > 0) {
            if (inStream.bad()) {
                throw std::runtime_error("Error reading from input stream");
            }
            size_t bytesRead = inStream.gcount();
            outLen = 0;
            if (!EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, inBuf.data(), static_cast<int>(bytesRead))) {
                throw std::runtime_error("Encryption failed during update");
            }
            std::cout << "--------------------------------1" << std::endl;
            std::cout << inBuf.data() << std::endl;
            std::cout << outBuf.data() << std::endl;
            std::cout << "--------------------------------2" << std::endl;
            if (outStream.bad()) {
                throw std::runtime_error("Error writing to output stream");
            }
            outStream.write(reinterpret_cast<const char*>(outBuf.data()), outLen);
        }

        if (!EVP_CipherFinal_ex(ctx.get(), outBuf.data() + outLen, &outLen)) {
            throw std::runtime_error("Encryption failed during finalization");
        }
    }

    void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        CryptFile(inStream, outStream, password, 1);
    };

    void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        CryptFile(inStream, outStream, password, 0);
    };

    std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) { 
        // Инициализация хеш-контекста с SHA-256
        std::unique_ptr<EVP_MD_CTX, decltype(&EVP_MD_CTX_free)> ctx(EVP_MD_CTX_new(), &EVP_MD_CTX_free);
        if (!ctx) {
            throw std::runtime_error("Failed to create hash context");
        }
        
        if (EVP_DigestInit_ex(ctx.get(), EVP_sha256(), nullptr) != 1) {
            throw std::runtime_error("Failed to initialize hash context");
        }
        
        // Буфер для чтения данных
        std::vector<unsigned char> buffer(4096);
        std::string result;
        
        // Чтение данных из потока и обновление хеша
        while (inStream.good()) {
            inStream.read(reinterpret_cast<char*>(buffer.data()), buffer.size());
            std::streamsize bytes_read = inStream.gcount();
            
            if (bytes_read > 0) {
                if (EVP_DigestUpdate(ctx.get(), buffer.data(), static_cast<size_t>(bytes_read)) != 1) {
                    throw std::runtime_error("Failed to update hash");
                }
            }
            
            // Проверка состояния потока
            if (inStream.bad()) {
                throw std::runtime_error("Error reading from stream");
            }
        }
        
        // Завершение хеширования
        std::vector<unsigned char> digest(EVP_MAX_MD_SIZE);
        unsigned int digest_len = 0;
        
        if (EVP_DigestFinal_ex(ctx.get(), digest.data(), &digest_len) != 1) {
            throw std::runtime_error("Failed to finalize hash");
        }
        
        // Преобразование в шестнадцатеричную строку
        std::stringstream ss;
        for (unsigned int i = 0; i < digest_len; ++i) {
            ss << std::hex << std::setfill('0') << std::setw(2) << static_cast<int>(digest[i]);
        }
        
        return ss.str();
    }

    AesCipherParams CryptoGuardCtx::Impl::CreateChiperParamsFromPassword(std::string_view password) {
        AesCipherParams params;
        constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

        int result = EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                                    reinterpret_cast<const unsigned char *>(password.data()), password.size(), 1,
                                    params.key.data(), params.iv.data());

        if (result == 0) {
            throw std::runtime_error{"Failed to create a key from password"};
        }

        return params;
    }


    CryptoGuardCtx::CryptoGuardCtx() : impl_(std::make_unique<Impl>()) {};
    CryptoGuardCtx::~CryptoGuardCtx() = default;
    std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) {
        return impl_->CalculateChecksum(inStream);
    };
    void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        impl_->EncryptFile(inStream, outStream, password);
    };
    void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) {
        impl_->DecryptFile(inStream, outStream, password);
    };
}  // namespace CryptoGuard

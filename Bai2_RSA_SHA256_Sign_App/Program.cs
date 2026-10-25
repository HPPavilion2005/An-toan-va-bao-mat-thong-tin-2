using System;
using System.Diagnostics;
using System.IO;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace Bai2_RSA_SHA256_DigitalSignature
{
    class Program
    {
        static void Main(string[] args)
        {
            Console.OutputEncoding = Encoding.UTF8;
            Console.WriteLine("========================================================================");
            Console.WriteLine(" BÀI TẬP 2: MÃ HOÁ BẤT ĐỐI XỨNG RSA, PEM ASN.1, SHA-256 & CHỮ KÝ SỐ    ");
            Console.WriteLine("========================================================================");

            string pubPemFile = "rsa_public.pem";
            string privPemFile = "rsa_private.pem";
            string encryptedBase64File = "encrypted_aes_key.b64";

            // 1 & 2. Sinh cặp khoá RSA 2048-bit và xuất ra file PEM (PKCS#1)
            using RSA rsaGenerator = RSA.Create(2048);
            File.WriteAllText(pubPemFile, rsaGenerator.ExportRSAPublicKeyPem());
            File.WriteAllText(privPemFile, rsaGenerator.ExportRSAPrivateKeyPem());
            Console.WriteLine("[1 & 2] Đã sinh cặp khoá RSA-2048 và lưu ra file rsa_public.pem / rsa_private.pem");

            // 3. View PEM và phân tích ý nghĩa từng vùng byte ASN.1 DER
            InspectPemBytes(pubPemFile, isPrivate: false);
            InspectPemBytes(privPemFile, isPrivate: true);

            // 4. Nhập file PEM Public Key -> lấy (n, e) | Nhập Private Key -> lấy (n, e, d, p, q, dp, dq, inverseQ)
            using RSA rsaPub = RSA.Create();
            rsaPub.ImportFromPem(File.ReadAllText(pubPemFile));
            RSAParameters pubParams = rsaPub.ExportParameters(includePrivateParameters: false);

            using RSA rsaPriv = RSA.Create();
            rsaPriv.ImportFromPem(File.ReadAllText(privPemFile));
            RSAParameters privParams = rsaPriv.ExportParameters(includePrivateParameters: true);

            Console.WriteLine("\n[4] Thông số toán học đọc từ file PEM:");
            Console.WriteLine($"    - Public Key  n ({pubParams.Modulus!.Length} bytes): {Convert.ToHexString(pubParams.Modulus)[..32]}...");
            Console.WriteLine($"    - Public Key  e ({pubParams.Exponent!.Length} bytes): 0x{Convert.ToHexString(pubParams.Exponent)} (Decimal: 65537)");
            Console.WriteLine($"    - Private Key d ({privParams.D!.Length} bytes): {Convert.ToHexString(privParams.D)[..32]}...");
            Console.WriteLine($"    - Prime p ({privParams.P!.Length}B), Prime q ({privParams.Q!.Length}B), DP, DQ, InverseQ đã nạp đầy đủ.");

            // 5. Mã hoá mảng byte <= 190 bytes (Ví dụ: Khoá AES-256 = 32 bytes) -> lưu dạng Base64 ra file
            // Lưu ý: Với RSA-2048 (256 bytes) + OAEP-SHA256, kích thước tối đa = 256 - 2*32 - 2 = 190 bytes.
            byte[] sampleAes256Key = RandomNumberGenerator.GetBytes(32);
            byte[] cipherBytes = rsaPub.Encrypt(sampleAes256Key, RSAEncryptionPadding.OaepSHA256);
            string cipherBase64 = Convert.ToBase64String(cipherBytes);
            File.WriteAllText(encryptedBase64File, cipherBase64);
            Console.WriteLine($"\n[5] Đã mã hoá khoá AES-256 (32 bytes <= 190 bytes) và lưu Base64 vào {encryptedBase64File}");

            // 6. Giải mã từ file PEM + file Base64 và đối sánh với dữ liệu nguồn
            byte[] loadedCipherBytes = Convert.FromBase64String(File.ReadAllText(encryptedBase64File));
            byte[] decryptedBytes = rsaPriv.Decrypt(loadedCipherBytes, RSAEncryptionPadding.OaepSHA256);
            bool match = CryptographicOperations.FixedTimeEquals(sampleAes256Key, decryptedBytes);
            Console.WriteLine($"[6] Giải mã từ PEM & so sánh với nguồn: {(match ? "TRÙNG KHỚP 100%" : "SAI LỆCH")}");

            // 7. Đánh giá tốc độ giữa khoá công khai (n, e nhỏ = 65537) và khoá bí mật (n, d lớn 2048-bit)
            BenchmarkRsaPublicVsPrivate(rsaPub, rsaPriv, iterations: 500);

            // 8. Sinh chuỗi băm SHA-256 và đánh giá Hiệu ứng thác đổ (Avalanche Effect) khi đầu vào đổi rất ít
            EvaluateSha256Avalanche(
                "Chuyen khoan 10.000.000 VND cho Nguyen Van A",
                "Chuyen khoan 10.000.001 VND cho Nguyen Van A"
            );

            // 9. Chữ ký số: Giải pháp để CÙNG DỮ LIỆU + CÙNG NGƯỜI KÝ (cùng Private Key)
            //    tạo ra CHỮ KÝ SỐ KHÁC NHAU ở mỗi lần ký (Sử dụng RSA-PSS với Salt ngẫu nhiên!)
            DemonstrateProbabilisticDigitalSignatures(rsaPub, rsaPriv);
        }

        static void InspectPemBytes(string pemFilePath, bool isPrivate)
        {
            string pem = File.ReadAllText(pemFilePath);
            string base64 = string.Join("", pem.Split(new[] { '\r', '\n' }, StringSplitOptions.RemoveEmptyEntries)[1..^1]);
            byte[] der = Convert.FromBase64String(base64);
            Console.WriteLine($"\n[3] Phân tích cấu trúc byte ASN.1 DER của {pemFilePath} (Tổng: {der.Length} bytes):");
            Console.WriteLine($"    - Byte[0] = 0x{der[0]:X2} (Tag SEQUENCE), tiếp theo là các trường Tag 0x02 (INTEGER).");
        }

        static void BenchmarkRsaPublicVsPrivate(RSA rsaPub, RSA rsaPriv, int iterations)
        {
            byte[] data = RandomNumberGenerator.GetBytes(32);
            byte[] cipher = rsaPub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);

            Stopwatch swPub = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
                _ = rsaPub.Encrypt(data, RSAEncryptionPadding.OaepSHA256);
            swPub.Stop();

            Stopwatch swPriv = Stopwatch.StartNew();
            for (int i = 0; i < iterations; i++)
                _ = rsaPriv.Decrypt(cipher, RSAEncryptionPadding.OaepSHA256);
            swPriv.Stop();

            Console.WriteLine($"\n[7] Đánh giá tốc độ ({iterations} lần thực hiện):");
            Console.WriteLine($"    - Dùng Public Key  (n, e=65537 bé) : {swPub.Elapsed.TotalMilliseconds:F2} ms");
            Console.WriteLine($"    - Dùng Private Key (n, d~2048b lớn): {swPriv.Elapsed.TotalMilliseconds:F2} ms (Chậm hơn {swPriv.Elapsed.TotalMilliseconds / swPub.Elapsed.TotalMilliseconds:F1} lần)");
        }

        static void EvaluateSha256Avalanche(string input1, string input2)
        {
            byte[] h1 = SHA256.HashData(Encoding.UTF8.GetBytes(input1));
            byte[] h2 = SHA256.HashData(Encoding.UTF8.GetBytes(input2));

            int diffBits = 0;
            for (int i = 0; i < h1.Length; i++)
                diffBits += BitOperations.PopCount((uint)(h1[i] ^ h2[i]));

            Console.WriteLine("\n[8] Đánh giá chuỗi băm SHA-256 (Avalanche Effect):");
            Console.WriteLine($"    - Đầu vào 1: {input1} -> SHA256: {Convert.ToHexString(h1)}");
            Console.WriteLine($"    - Đầu vào 2: {input2} -> SHA256: {Convert.ToHexString(h2)}");
            Console.WriteLine($"    - Số bit thay đổi: {diffBits}/256 bits ({diffBits * 100.0 / 256.0:F2}% ~ xấp xỉ 50% lý tưởng)");
        }

        static void DemonstrateProbabilisticDigitalSignatures(RSA rsaPub, RSA rsaPriv)
        {
            byte[] data = Encoding.UTF8.GetBytes("Hop dong dien tu so 2026-ATTT - Noi dung khong doi");

            // Phương pháp chuẩn: RSA-PSS (RSASignaturePadding.Pss) tự động chèn Salt ngẫu nhiên vào khối đệm MGF1
            byte[] sigPss1 = rsaPriv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            byte[] sigPss2 = rsaPriv.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            bool verify1 = rsaPub.VerifyData(data, sigPss1, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);
            bool verify2 = rsaPub.VerifyData(data, sigPss2, HashAlgorithmName.SHA256, RSASignaturePadding.Pss);

            Console.WriteLine("\n[9] Chữ ký số xác suất RSA-PSS (Cùng dữ liệu + Cùng Private Key => Chữ ký khác nhau):");
            Console.WriteLine($"    - Chữ ký lần 1 (Base64): {Convert.ToBase64String(sigPss1)[..48]}...");
            Console.WriteLine($"    - Chữ ký lần 2 (Base64): {Convert.ToBase64String(sigPss2)[..48]}...");
            Console.WriteLine($"    - Hai chữ ký có khác nhau không? : {! CryptographicOperations.FixedTimeEquals(sigPss1, sigPss2)}");
            Console.WriteLine($"    - Xác thực với Public Key       : Lần 1 = {verify1}, Lần 2 = {verify2}");
        }
    }
}
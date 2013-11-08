Key_encrypt = Hash(Salt, Data)
Key_storage = Hash(Key_encrypt)

Compressed_Data = Compress(Data)
IV, Encrypted_Data = Encrypt(Compressed_Data, Key_Encrypt)

Hash = SHA256
Encrypt = AES-256-CTR

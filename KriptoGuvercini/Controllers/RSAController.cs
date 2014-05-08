using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Web;
using System.Web.Mvc;
using KriptoGuvercini.Models;
using KriptoGuvercini.src;

namespace KriptoGuvercini.Controllers
{
    public class RSAController : BaseController
    {
        private readonly KriptoGuverciniDBEntities _db = new KriptoGuverciniDBEntities();

        public void CreateKeyPair(string userId, string password)
        {
            var user = _db.AspNetUsers.Find(userId);

            using (var rsa = new RSACryptoServiceProvider(2048))
            {

                var keypair = rsa.ToXmlString(true);

                var salt = new Byte[16];

                using (var crpyto = new RNGCryptoServiceProvider())
                {
                    crpyto.GetNonZeroBytes(salt);
                }

                using (var encryptor = Aes.Create())
                {
                    using (var pdb = new Rfc2898DeriveBytes(password, salt))
                    {
                        var aesKey = pdb.GetBytes(32);
                        var encrypted = Encrypt(keypair, aesKey, encryptor.IV);
                        user.IV = encryptor.IV;
                        user.KeyPair = encrypted;
                        user.Salt = salt;
                        user.DeleteAfterRead = false;
                        user.PublicKey = rsa.ToXmlString(false);
                        _db.SaveChanges();
                    }

                }

            }

            //return View("../Home/Index");
        }

        public void ChangeAesPassword(string userId, string oldPw, string newPw)
        {
            var user = _db.AspNetUsers.Find(userId);
            string rsaKey;

            using (var pdb = new Rfc2898DeriveBytes(oldPw, user.Salt))
            {
                var aesKey = pdb.GetBytes(32);

                // Create an Aes object
                // with the specified key and IV.
                using (var aesAlg = Aes.Create())
                {
                    aesAlg.Key = aesKey;
                    aesAlg.IV = user.IV;
                    aesAlg.Padding = PaddingMode.Zeros;
                    // Create a decrytor to perform the stream transform.
                    ICryptoTransform decryptor = aesAlg.CreateDecryptor(aesAlg.Key
                        , aesAlg.IV);

                    // Create the streams used for decryption.
                    using (var msDecrypt = new MemoryStream(user.KeyPair))
                    {
                        using (var csDecrypt = new CryptoStream(msDecrypt
                            , decryptor, CryptoStreamMode.Read))
                        {
                            using (var srDecrypt = new StreamReader(
                                csDecrypt))
                            {

                                // Read the decrypted bytes from the decrypting 
                                // and place them in a string.
                                rsaKey = srDecrypt.ReadToEnd();
                            }
                        }
                    }

                }
            }

            var salt = new Byte[16];

            using (var crpyto = new RNGCryptoServiceProvider())
            {
                crpyto.GetNonZeroBytes(salt);
            }

            using (var encryptor = Aes.Create())
            {
                using (var pdb = new Rfc2898DeriveBytes(newPw, salt))
                {
                    var aesKey = pdb.GetBytes(32);
                    var encrypted = Encrypt(rsaKey, aesKey, encryptor.IV);
                    user.IV = encryptor.IV;
                    user.KeyPair = encrypted;
                    user.Salt = salt;
                    _db.SaveChanges();
                }

            }



        }


        private byte[] Encrypt(string keypair, byte[] key, byte[] IV)
        {

            byte[] encrypted;
            using (var aes = Aes.Create())
            {
                aes.Key = key;
                aes.IV = IV;
                aes.Padding = PaddingMode.Zeros;
                var encryptor = aes.CreateEncryptor(aes.Key
, aes.IV);

                using (var msEncrypt = new MemoryStream())
                {
                    using (var csEncrypt = new CryptoStream(msEncrypt
, encryptor, CryptoStreamMode.Write))
                    {
                        using (var swEncrypt = new StreamWriter(
csEncrypt))
                        {

                            //Write all data to the stream.
                            swEncrypt.Write(keypair);
                        }
                        encrypted = msEncrypt.ToArray();

                    }

                }

            }
            return encrypted;
        }


	}
}
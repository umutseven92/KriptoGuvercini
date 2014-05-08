using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Net;
using System.Security.Cryptography;
using System.Text;
using System.Web;
using System.Web.Mvc;
using KriptoGuvercini.Models;
using KriptoGuvercini.src;
using Microsoft.AspNet.Identity;
using Microsoft.AspNet.Identity.EntityFramework;

namespace KriptoGuvercini.Controllers
{
    [Authorize]
    public class MessageController : BaseController
    {
        private readonly KriptoGuverciniDBEntities _db = new KriptoGuverciniDBEntities();

        // GET: /Message/

        public ActionResult Index()
        {
            var userId = User.Identity.GetUserId();
            var messages = _db.Messages.Where(m => m.ToID == userId);


            return View(messages.ToList());
        }

        [HttpPost]
        public ActionResult Index(string txtPassword, int txtId)
        {
            if (string.IsNullOrWhiteSpace(txtPassword))
            {
                if (CultureHelper.GetCurrentCulture() == "tr-TR")
                {
                    TempData["passwordError"] = "Lütfen şifrenizi giriniz.";
                }
                else if (CultureHelper.GetCurrentCulture() == "en-US")
                {
                    TempData["passwordError"] = "Please enter your password.";
                }
                return RedirectToAction("Index");
            }
            TempData["param"] = txtPassword;
            //if password is true
            var userManager =
                new UserManager<ApplicationUser>(new UserStore<ApplicationUser>(new ApplicationDbContext()));
            var result = userManager.PasswordHasher.VerifyHashedPassword(
                 _db.AspNetUsers.Find(User.Identity.GetUserId()).PasswordHash, txtPassword);

            if (result == PasswordVerificationResult.Failed)
            {
                TempData["param"] = string.Empty;
                TempData["validated"] = false;
                if (CultureHelper.GetCurrentCulture() == "tr-TR")
                {
                    TempData["passwordError"] = "Şifreniz yanlış. Lütfen tekrar deneyiniz.";
                }
                else if (CultureHelper.GetCurrentCulture() == "en-US")
                {
                    TempData["passwordError"] = "Wrong password. Please try again.";
                }

               
                return RedirectToAction("Index");
            }

            TempData["validated"] = true;
            return RedirectToAction("Details", new { id = txtId });


        }

        // GET: /Message/Details/5
        public ActionResult Details(int? id)
        {
            if (id == null || TempData["validated"] == null || (bool)TempData["validated"] == false)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            TempData["validated"] = false;
            var message = _db.Messages.Find(id);
            var userId = User.Identity.GetUserId();

            if (message == null)
            {
                return HttpNotFound();
            }


            var user = _db.AspNetUsers.Find(userId);
            string rsaKey;
            using (var pdb = new Rfc2898DeriveBytes(TempData["param"].ToString(), user.Salt))
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

            using (var rsa = new RSACryptoServiceProvider())
            {
                rsa.FromXmlString(rsaKey);
                var decryptedMessage = rsa.Decrypt(message.MessageBody, false);
                ViewBag.EncryptedBody = Encoding.UTF8.GetString(decryptedMessage);
                ViewBag.UserName = _db.AspNetUsers.Find(message.FromID).UserName;
                ViewBag.SentDate = message.SentDate;
            }

            message.Read = true;
            if (_db.AspNetUsers.Find(User.Identity.GetUserId()).DeleteAfterRead == true)
            {
                _db.Messages.Remove(message);

            }
            _db.SaveChanges();
            return View();
        }


        // GET: /Message/Create
        public ActionResult Create(string error = "")
        {

            return View();
        }



        // POST: /Message/Create
        // To protect from overposting attacks, please enable the specific properties you want to bind to, for 
        // more details see http://go.microsoft.com/fwlink/?LinkId=317598.
        [HttpPost]
        [ValidateAntiForgeryToken]
        public ActionResult Create([Bind(Include = "Id")] Message message, string txtUserName, string txtMessage)
        {
            if (ModelState.IsValid)
            {
                if (string.IsNullOrWhiteSpace(txtMessage))
                {
                    if (CultureHelper.GetCurrentCulture() == "tr-TR")
                    {
                        TempData["error"] = "Lütfen mesajınızı giriniz.";
                    }
                    else if (CultureHelper.GetCurrentCulture() == "en-US")
                    {
                        TempData["error"] = "Please enter your message.";
                    }
                    
                    return RedirectToAction("Create", "Message");
                }
                AspNetUser userToSend;
                try
                {
                    userToSend = _db.AspNetUsers.Single(u => u.UserName == txtUserName);
                }
                catch (InvalidOperationException ex)
                {
                    if (CultureHelper.GetCurrentCulture() == "tr-TR")
                    {
                        TempData["error"] = "Alıcı bulunamadi.";
                    }
                    else if (CultureHelper.GetCurrentCulture() == "en-US")
                    {
                        TempData["error"] = "Receiver can't be found.";
                    }
                    
                    return RedirectToAction("Create", "Message");
                }
                catch (Exception ex)
                {
                    if (CultureHelper.GetCurrentCulture() == "tr-TR")
                    {
                        TempData["error"] = "Bir hata olustu.";
                    }
                    else if (CultureHelper.GetCurrentCulture() == "en-US")
                    {
                        TempData["error"] = "An error occurred.";
                    }
                    
                    return RedirectToAction("Create", "Message");
                }

                var userSending = _db.AspNetUsers.Find(User.Identity.GetUserId());

                using (var rsa = new RSACryptoServiceProvider())
                {
                    rsa.FromXmlString(userToSend.PublicKey);
                    var messageByte = rsa.Encrypt(Encoding.UTF8.GetBytes(txtMessage), false);
                    message.MessageBody = messageByte;
                    message.FromID = userSending.Id;
                    message.ToID = userToSend.Id;
                    message.SentDate = DateTime.Now;
                    message.Read = false;
                    _db.Messages.Add(message);
                    _db.SaveChanges();
                }
            }

            return RedirectToAction("Index");
        }



        // GET: /Message/Delete/5
        public ActionResult Delete(int? id)
        {
            if (id == null)
            {
                return new HttpStatusCodeResult(HttpStatusCode.BadRequest);
            }
            Message message = _db.Messages.Find(id);
            if (message == null)
            {
                return HttpNotFound();
            }
            return View(message);
        }

        // POST: /Message/Delete/5
        [HttpPost, ActionName("Delete")]
        [ValidateAntiForgeryToken]
        public ActionResult DeleteConfirmed(int id)
        {
            Message message = _db.Messages.Find(id);
            _db.Messages.Remove(message);
            _db.SaveChanges();
            return RedirectToAction("Index");
        }

        protected override void Dispose(bool disposing)
        {
            if (disposing)
            {
                _db.Dispose();
            }
            base.Dispose(disposing);
        }
    }
}
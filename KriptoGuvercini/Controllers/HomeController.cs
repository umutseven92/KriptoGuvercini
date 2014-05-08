using System;
using System.Collections.Generic;
using System.Linq;
using System.Web;
using System.Web.Mvc;
using KriptoGuvercini.src;


namespace KriptoGuvercini.Controllers
{
    public class HomeController : BaseController
    {
        public ActionResult Index()
        {
            return View();
        }

        public ActionResult About()
        {
            
            return View();
        }

        public ActionResult Error()
        {
            return View();

        }
        public ActionResult SetCulture(string culture)
        {
            // Validate input
            culture = CultureHelper.GetImplementedCulture(culture);
            RouteData.Values["culture"] = culture;  // set culture
            var segCount = HttpContext.Request.UrlReferrer.Segments.Count();
            var refUrl = "/" + culture + "/";

            for (int i = 2; i < segCount; i++)
            {
                refUrl += HttpContext.Request.UrlReferrer.Segments[i];
            }

            return Redirect(refUrl);
        }     
    }
}